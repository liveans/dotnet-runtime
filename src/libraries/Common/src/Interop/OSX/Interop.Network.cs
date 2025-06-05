using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

internal static partial class Interop
{
    internal static partial class NW
    {
        [LibraryImport(Interop.Libraries.AppleNetworkNative, EntryPoint = "AppleNetNative_NWRelease")]
        internal static partial void Release(SafeNWHandle nwHandle);
        [LibraryImport(Interop.Libraries.AppleNetworkNative, EntryPoint = "AppleNetNative_NWRetain")]
        internal static partial void Retain(SafeNWHandle nwHandle);
        internal static partial class NWEndpoint
        {
            [LibraryImport(Interop.Libraries.AppleNetworkNative, EntryPoint = "AppleNetNative_NWEndpoint_CreateHost")]
            internal static partial SafeNWEndpointHandle CreateHost(string host, ushort port);

            [LibraryImport(Interop.Libraries.AppleNetworkNative, EntryPoint = "AppleNetNative_NWEndpoint_GetHostname")]
            internal static partial string GetHostname(SafeNWEndpointHandle handle);

            [LibraryImport(Interop.Libraries.AppleNetworkNative, EntryPoint = "AppleNetNative_NWEndpoint_GetPort")]
            internal static partial ushort GetPort(SafeNWEndpointHandle handle);

            [LibraryImport(Interop.Libraries.AppleNetworkNative, EntryPoint = "AppleNetNative_NWEndpoint_CreateAddress")]
            internal static partial SafeNWEndpointHandle CreateAddress(IntPtr socketAddressHandle);

            [LibraryImport(Interop.Libraries.AppleNetworkNative, EntryPoint = "AppleNetNative_NWEndpoint_GetAddress")]
            internal static partial IntPtr GetAddress(SafeNWEndpointHandle handle);

            [LibraryImport(Interop.Libraries.AppleNetworkNative, EntryPoint = "AppleNetNative_NWEndpoint_CreateURL")]
            internal static partial SafeNWEndpointHandle CreateURL(string url);

            [LibraryImport(Interop.Libraries.AppleNetworkNative, EntryPoint = "AppleNetNative_NWEndpoint_GetURL")]
            internal static partial string GetURL(SafeNWEndpointHandle handle);
        }

        internal static partial class NWParameters
        {
            internal delegate void ConfigureProtocolDelegate(SafeNWOptionsHandle optionsHandle);
            [LibraryImport(Interop.Libraries.AppleNetworkNative, EntryPoint = "AppleNetNative_NWParameters_Create")]
            internal static partial SafeNWParametersHandle Create();

            [LibraryImport(Interop.Libraries.AppleNetworkNative, EntryPoint = "AppleNetNative_NWParameters_CreateSecureTcp")]
            internal static partial SafeNWParametersHandle CreateSecureTcp(ConfigureProtocolDelegate configureTls, ConfigureProtocolDelegate configureTcp);

            [LibraryImport(Interop.Libraries.AppleNetworkNative, EntryPoint = "AppleNetNative_NWParameters_CreateSecureUdp")]
            internal static partial SafeNWParametersHandle CreateSecureUdp(ConfigureProtocolDelegate configureDtls, ConfigureProtocolDelegate configureUdp);

            [LibraryImport(Interop.Libraries.AppleNetworkNative, EntryPoint = "AppleNetNative_NWParameters_CreateQuic")]
            internal static partial SafeNWParametersHandle CreateQuic(ConfigureProtocolDelegate configureQuic);

            [LibraryImport(Interop.Libraries.AppleNetworkNative, EntryPoint = "AppleNetNative_NWParameters_CreateCustomIp")]
            internal static partial SafeNWParametersHandle CreateCustomIp(byte customIpProtocolNumber, ConfigureProtocolDelegate configureCustomIp);

            [LibraryImport(Interop.Libraries.AppleNetworkNative, EntryPoint = "AppleNetNative_NWParameters_Copy")]
            internal static partial SafeNWParametersHandle Copy(SafeNWParametersHandle handle);
        }

        internal static partial class NWConnection
        {
            internal enum State
            {
                Invalid = 0,
                Waiting = 1,
                Preparing = 2,
                Ready = 3,
                Failed = 4,
                Cancelled = 5,
            }
            internal delegate void StateChangedHandler(State connectionState, SafeNWErrorHandle errorHandle);
            internal delegate void SendCompletionHandler(SafeNWErrorHandle errorHandle);
            internal delegate void ReceiveCompletionHandler(Span<byte> buffer, bool isComplete, SafeNWErrorHandle errorHandle);

            [LibraryImport(Interop.Libraries.AppleNetworkNative, EntryPoint = "AppleNetNative_NWConnection_Create")]
            internal static partial SafeNWConnectionHandle Create(SafeNWEndpointHandle endpointHandle, SafeNWParametersHandle parametersHandle);

            [LibraryImport(Interop.Libraries.AppleNetworkNative, EntryPoint = "AppleNetNative_NWConnection_Start")]
            internal static partial void Start(SafeNWConnectionHandle handle);

            [LibraryImport(Interop.Libraries.AppleNetworkNative, EntryPoint = "AppleNetNative_NWConnection_Restart")]
            internal static partial void Restart(SafeNWConnectionHandle handle);

            [LibraryImport(Interop.Libraries.AppleNetworkNative, EntryPoint = "AppleNetNative_NWConnection_SetStateChangedHandler")]
            internal static partial void SetStateChangedHandler(SafeNWConnectionHandle handle, StateChangedHandler handler);

            [LibraryImport(Interop.Libraries.AppleNetworkNative, EntryPoint = "AppleNetNative_NWConnection_Send")]
            internal static partial void Send(SafeNWConnectionHandle handle, ReadOnlySpan<byte> buffer, nuint length, bool isComplete, SendCompletionHandler handler);

            [LibraryImport(Interop.Libraries.AppleNetworkNative, EntryPoint = "AppleNetNative_NWConnection_Receive")]
            internal static partial void Receive(SafeNWConnectionHandle handle, uint minimumIncompleteLength, uint maxLength, ReceiveCompletionHandler handler);

            [LibraryImport(Interop.Libraries.AppleNetworkNative, EntryPoint = "AppleNetNative_NWConnection_ReceiveMessage")]
            internal static partial void ReceiveMessage(SafeNWConnectionHandle handle, ReceiveCompletionHandler handler);

            [LibraryImport(Interop.Libraries.AppleNetworkNative, EntryPoint = "AppleNetNative_NWConnection_Cancel")]
            internal static partial void Cancel(SafeNWConnectionHandle handle);

            [LibraryImport(Interop.Libraries.AppleNetworkNative, EntryPoint = "AppleNetNative_NWConnection_ForceCancel")]
            internal static partial void ForceCancel(SafeNWConnectionHandle handle);

            [LibraryImport(Interop.Libraries.AppleNetworkNative, EntryPoint = "AppleNetNative_NWConnection_CancelCurrentEndpoint")]
            internal static partial void CancelCurrentEndpoint(SafeNWConnectionHandle handle);
        }

        internal static partial class NWError
        {
            internal enum Domain
            {
                Invalid = 0,
                Posix = 1,
                Dns = 2,
                Tls = 3,
            }

            [LibraryImport(Interop.Libraries.AppleNetworkNative, EntryPoint = "AppleNetNative_NWError_GetErrorDomain")]
            internal static partial Domain GetErrorDomain(SafeNWErrorHandle handle);

            [LibraryImport(Interop.Libraries.AppleNetworkNative, EntryPoint = "AppleNetNative_NWError_GetErrorCode")]
            internal static partial int GetErrorCode(SafeNWErrorHandle handle);
        }
    }
    
}

namespace System.Net
{
    internal sealed class SafeNWHandle : SafeHandle
    {
        public SafeNWHandle()
            : base(IntPtr.Zero, ownsHandle: true)
        {
        }

        public override bool IsInvalid => handle == IntPtr.Zero;

        internal SafeNWHandle(IntPtr invalidHandleValue, bool ownsHandle)
            : base(invalidHandleValue, ownsHandle)
        {
            if (!IsInvalid)
            {
                Interop.NW.Retain(this);
            }
        }

        protected override bool ReleaseHandle()
        {
            Interop.NW.Release(this);
            return true;
        }
    }
    
    internal sealed class SafeNWEndpointHandle : SafeNWHandle
    {
    }

    internal sealed class SafeNWParametersHandle : SafeNWHandle
    {
    }

    internal sealed class SafeNWOptionsHandle : SafeNWHandle
    {
    }

    internal sealed class SafeNWConnectionHandle : SafeNWHandle
    {
    }

    internal sealed class SafeNWErrorHandle : SafeNWHandle
    {
    }
}