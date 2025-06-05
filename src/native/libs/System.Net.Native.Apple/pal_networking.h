// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#pragma once
#include "pal_compiler.h"
#include <stdint.h>
#include <Network/Network.h>

// NWEndpoint
PALEXPORT nw_endpoint_t AppleNetNative_NWEndpoint_CreateHost(const char* host, uint16_t port);
PALEXPORT const char* AppleNetNative_NWEndpoint_GetHostname(nw_endpoint_t endpoint);
PALEXPORT uint16_t AppleNetNative_NWEndpoint_GetPort(nw_endpoint_t endpoint);

PALEXPORT nw_endpoint_t AppleNetNative_NWEndpoint_CreateAddress(const struct sockaddr* address);
PALEXPORT const struct sockaddr* AppleNetNative_NWEndpoint_GetAddress(nw_endpoint_t endpoint);

PALEXPORT nw_endpoint_t AppleNetNative_NWEndpoint_CreateURL(const char* url);
PALEXPORT const char* AppleNetNative_NWEndpoint_GetURL(nw_endpoint_t endpoint);

//NWParameters
typedef void(*C_nw_parameters_configure_protocol_block_t)(nw_protocol_options_t options);
PALEXPORT nw_parameters_t AppleNetNative_NWParameters_Create(void);
PALEXPORT nw_parameters_t AppleNetNative_NWParameters_CreateSecureTcp(C_nw_parameters_configure_protocol_block_t configure_tls, C_nw_parameters_configure_protocol_block_t configure_tcp);
PALEXPORT nw_parameters_t AppleNetNative_NWParameters_CreateSecureUdp(C_nw_parameters_configure_protocol_block_t configure_dtls, C_nw_parameters_configure_protocol_block_t configure_udp);
PALEXPORT nw_parameters_t AppleNetNative_NWParameters_CreateQuic(C_nw_parameters_configure_protocol_block_t configure_quic);
PALEXPORT nw_parameters_t AppleNetNative_NWParameters_CreateCustomIp(uint8_t custom_ip_protocol_number, C_nw_parameters_configure_protocol_block_t configure_custom_ip);
PALEXPORT nw_parameters_t AppleNetNative_NWParameters_Copy(nw_parameters_t parameters);

PALEXPORT nw_connection_t AppleNetNative_NWConnection_Create(nw_endpoint_t endpoint, nw_parameters_t parameters);
PALEXPORT void AppleNetNative_NWConnection_Start(nw_connection_t connection);
PALEXPORT void AppleNetNative_NWConnection_Restart(nw_connection_t connection);

typedef void(*C_nw_connection_state_changed_handler_t)(nw_connection_state_t state, nw_error_t error);
PALEXPORT void AppleNetNative_NWConnection_SetStateChangedHandler(nw_connection_t connection, C_nw_connection_state_changed_handler_t handler);

typedef void(*C_nw_connection_send_completion_t)(nw_error_t error);
PALEXPORT void AppleNetNative_NWConnection_Send(nw_connection_t connection, const uint8_t* buffer, size_t length, bool is_complete, C_nw_connection_send_completion_t completion);

typedef void(*C_nw_connection_receive_completion_t)(const uint8_t* buffer, size_t length, bool is_complete, nw_error_t error);
PALEXPORT void AppleNetNative_NWConnection_Receive(nw_connection_t connection, uint32_t minimum_incomplete_length, uint32_t max_length, C_nw_connection_receive_completion_t completion);
PALEXPORT void AppleNetNative_NWConnection_ReceiveMessage(nw_connection_t connection, C_nw_connection_receive_completion_t completion);

PALEXPORT void AppleNetNative_NWConnection_Cancel(nw_connection_t connection);
PALEXPORT void AppleNetNative_NWConnection_ForceCancel(nw_connection_t connection);
PALEXPORT void AppleNetNative_NWConnection_CancelCurrentEndpoint(nw_connection_t connection);

PALEXPORT nw_error_domain_t AppleNetNative_NWError_GetErrorDomain(nw_error_t error);
PALEXPORT int AppleNetNative_NWError_GetErrorCode(nw_error_t error);

PALEXPORT void AppleNetNative_NWRelease(void* obj);
PALEXPORT void AppleNetNative_NWRetain(void* obj);
