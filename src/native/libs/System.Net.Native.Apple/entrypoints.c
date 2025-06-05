// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#include <minipal/entrypoints.h>

// Include System.Net.Native.Apple headers
#include "pal_networking.h"
#include "pal_networking_tls.h"

static const Entry s_netAppleNative[] =
{
    DllImportEntry(AppleNetNative_NWEndpoint_CreateHost)
    DllImportEntry(AppleNetNative_NWEndpoint_GetHostname)
    DllImportEntry(AppleNetNative_NWEndpoint_GetPort)
    DllImportEntry(AppleNetNative_NWEndpoint_CreateAddress)
    DllImportEntry(AppleNetNative_NWEndpoint_GetAddress)
    DllImportEntry(AppleNetNative_NWEndpoint_CreateURL)
    DllImportEntry(AppleNetNative_NWEndpoint_GetURL)
    DllImportEntry(AppleNetNative_NWParameters_Create)
    DllImportEntry(AppleNetNative_NWParameters_CreateSecureTcp)
    DllImportEntry(AppleNetNative_NWParameters_CreateSecureUdp)
    DllImportEntry(AppleNetNative_NWParameters_CreateQuic)
    DllImportEntry(AppleNetNative_NWParameters_CreateCustomIp)
    DllImportEntry(AppleNetNative_NWParameters_Copy)
    DllImportEntry(AppleNetNative_NWConnection_Create)
    DllImportEntry(AppleNetNative_NWConnection_Start)
    DllImportEntry(AppleNetNative_NWConnection_Restart)
    DllImportEntry(AppleNetNative_NWConnection_SetStateChangedHandler)
    DllImportEntry(AppleNetNative_NWConnection_Send)
    DllImportEntry(AppleNetNative_NWConnection_Receive)
    DllImportEntry(AppleNetNative_NWConnection_ReceiveMessage)
    DllImportEntry(AppleNetNative_NWConnection_Cancel)
    DllImportEntry(AppleNetNative_NWConnection_ForceCancel)
    DllImportEntry(AppleNetNative_NWConnection_CancelCurrentEndpoint)
    DllImportEntry(AppleNetNative_NWError_GetErrorDomain)
    DllImportEntry(AppleNetNative_NWError_GetErrorCode)
    DllImportEntry(AppleNetNative_NWRelease)
    DllImportEntry(AppleNetNative_NWRetain)
    DllImportEntry(AppleNetNative_NwInit)
    DllImportEntry(AppleNetNative_NwCreateClientContext)
    DllImportEntry(AppleNetNative_NwSendToConnection)
    DllImportEntry(AppleNetNative_NwReadFromConnection)
    DllImportEntry(AppleNetNative_NwProcessInputData)
    DllImportEntry(AppleNetNative_NwSetTlsOptions)
    DllImportEntry(AppleNetNative_NwStartTlsHandshake)
    DllImportEntry(AppleNetNative_NwGetConnectionInfo)
    DllImportEntry(AppleNetNative_NwCopyCertChain)
    DllImportEntry(AppleNetNative_NwCancelConnection)
};

EXTERN_C const void* NetAppleResolveDllImport(const char* name);

EXTERN_C const void* NetAppleResolveDllImport(const char* name)
{
    return minipal_resolve_dllimport(s_netAppleNative, ARRAY_SIZE(s_netAppleNative), name);
}
