// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#include "pal_networking.h"
#import <Foundation/Foundation.h>
#include <dispatch/dispatch.h>
#include <dispatch/queue.h>
#include <stdio.h>

nw_endpoint_t AppleNetNative_NWEndpoint_CreateHost(const char* host, uint16_t port)
{
    char str_port[6];
    snprintf(str_port, sizeof(str_port), "%u", port);
    return nw_endpoint_create_host(host, str_port);
}

const char* AppleNetNative_NWEndpoint_GetHostname(nw_endpoint_t endpoint)
{
    return nw_endpoint_get_hostname(endpoint);
}

uint16_t AppleNetNative_NWEndpoint_GetPort(nw_endpoint_t endpoint)
{
    return nw_endpoint_get_port(endpoint);
}

nw_endpoint_t AppleNetNative_NWEndpoint_CreateAddress(const struct sockaddr* address)
{
    return nw_endpoint_create_address(address);
}

const struct sockaddr* AppleNetNative_NWEndpoint_GetAddress(nw_endpoint_t endpoint)
{
    return nw_endpoint_get_address(endpoint);
}

nw_endpoint_t AppleNetNative_NWEndpoint_CreateURL(const char* url)
{
    return nw_endpoint_create_url(url);
}

const char* AppleNetNative_NWEndpoint_GetURL(nw_endpoint_t endpoint)
{
    return nw_endpoint_get_url(endpoint);
}

nw_parameters_t AppleNetNative_NWParameters_Create(void)
{
    return nw_parameters_create();
}

nw_parameters_t AppleNetNative_NWParameters_CreateSecureTcp(C_nw_parameters_configure_protocol_block_t configure_tls, C_nw_parameters_configure_protocol_block_t configure_tcp)
{
    nw_parameters_t parameters = nw_parameters_create_secure_tcp(^(nw_protocol_options_t options) {
        configure_tls(options);
    }, ^(nw_protocol_options_t options) {
        configure_tcp(options);
    });
    return parameters;
}

nw_parameters_t AppleNetNative_NWParameters_CreateSecureUdp(C_nw_parameters_configure_protocol_block_t configure_dtls, C_nw_parameters_configure_protocol_block_t configure_udp)
{
    return nw_parameters_create_secure_udp(^(nw_protocol_options_t options) {
        configure_dtls(options);
    }, ^(nw_protocol_options_t options) {
        configure_udp(options);
    });
}

nw_parameters_t AppleNetNative_NWParameters_CreateQuic(C_nw_parameters_configure_protocol_block_t configure_quic)
{
    return nw_parameters_create_quic(^(nw_protocol_options_t options) {
        configure_quic(options);
    });
}

nw_parameters_t AppleNetNative_NWParameters_CreateCustomIp(uint8_t custom_ip_protocol_number, C_nw_parameters_configure_protocol_block_t configure_custom_ip)
{
    return nw_parameters_create_custom_ip(custom_ip_protocol_number, ^(nw_protocol_options_t options) {
        configure_custom_ip(options);
    });
}

nw_parameters_t AppleNetNative_NWParameters_Copy(nw_parameters_t parameters)
{
    return nw_parameters_copy(parameters);
}

nw_connection_t AppleNetNative_NWConnection_Create(nw_endpoint_t endpoint, nw_parameters_t parameters)
{
    nw_connection_t connection = nw_connection_create(endpoint, parameters);
    nw_connection_set_queue(connection, dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0));
    return connection;
}

void AppleNetNative_NWConnection_Start(nw_connection_t connection)
{
    nw_connection_start(connection);
}

void AppleNetNative_NWConnection_Restart(nw_connection_t connection)
{
    nw_connection_restart(connection);
}

void AppleNetNative_NWConnection_SetStateChangedHandler(nw_connection_t connection, C_nw_connection_state_changed_handler_t handler)
{
    nw_connection_set_state_changed_handler(connection, ^(nw_connection_state_t state, nw_error_t error) {
        handler(state, error);
    });
}

void AppleNetNative_NWConnection_Send(nw_connection_t connection, const uint8_t* buffer, size_t length, bool is_complete, C_nw_connection_send_completion_t completion)
{
    uint8_t* buffer_copy = malloc(sizeof(uint8_t) * length);
    memcpy(buffer_copy, buffer, sizeof(uint8_t) * length);
    if (buffer_copy == NULL)
    {
        // Create custom error and call completion with it.
        // completion(NULL);
        return;
    }
    dispatch_data_t data = dispatch_data_create(buffer_copy, length, dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), DISPATCH_DATA_DESTRUCTOR_FREE);
    nw_connection_send(connection, data, NW_CONNECTION_DEFAULT_MESSAGE_CONTEXT, is_complete, ^(nw_error_t send_error) {
        completion(send_error);
    });
}

void AppleNetNative_NWConnection_Receive(nw_connection_t connection, uint32_t minimum_incomplete_length, uint32_t max_length, C_nw_connection_receive_completion_t completion)
{
    nw_connection_receive(connection, minimum_incomplete_length, max_length, ^(dispatch_data_t content, nw_content_context_t context, bool is_complete, nw_error_t receive_error) {
        (void)context;
        NSData* data = (NSData*)content;
        completion((const uint8_t *)[data bytes], dispatch_data_get_size(content), is_complete, receive_error);
    });
}

void AppleNetNative_NWConnection_ReceiveMessage(nw_connection_t connection, C_nw_connection_receive_completion_t completion)
{
    nw_connection_receive_message(connection, ^(dispatch_data_t content, nw_content_context_t context, bool is_complete, nw_error_t receive_error) {
        (void)context;
        NSData* data = (NSData*)content;
        completion((const uint8_t *)[data bytes], dispatch_data_get_size(content), is_complete, receive_error);
    });
}

void AppleNetNative_NWConnection_Cancel(nw_connection_t connection)
{
    nw_connection_cancel(connection);
}

void AppleNetNative_NWConnection_ForceCancel(nw_connection_t connection)
{
    nw_connection_force_cancel(connection);
}

void AppleNetNative_NWConnection_CancelCurrentEndpoint(nw_connection_t connection)
{
    nw_connection_cancel_current_endpoint(connection);
}

nw_error_domain_t AppleNetNative_NWError_GetErrorDomain(nw_error_t error)
{
    return nw_error_get_error_domain(error);
}

int AppleNetNative_NWError_GetErrorCode(nw_error_t error)
{
    return nw_error_get_error_code(error);
}

void AppleNetNative_NWRelease(void* obj)
{
    nw_release(obj);
}

void AppleNetNative_NWRetain(void* obj)
{
    nw_retain(obj);
}
