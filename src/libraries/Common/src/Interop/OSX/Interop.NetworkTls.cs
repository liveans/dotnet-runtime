using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using System.Security.Authentication;

internal static partial class Interop
{
    internal static partial class NetworkFramework
    {
        [LibraryImport(Interop.Libraries.AppleNetworkNative, EntryPoint = "AppleNetNative_NWRelease")]
        internal static partial void Release(SafeNetworkFrameworkHandle nwHandle);
        [LibraryImport(Interop.Libraries.AppleNetworkNative, EntryPoint = "AppleNetNative_NWRetain")]
        internal static partial void Retain(SafeNetworkFrameworkHandle nwHandle);
        internal static partial class Error
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

        internal static partial class Tls
        {
            [LibraryImport(Interop.Libraries.AppleNetworkNative, EntryPoint = "AppleNetNative_NwCreateClientContext")]
            internal static partial SafeNetworkFrameworkConnectionHandle CreateClientContext();

            [LibraryImport(Interop.Libraries.AppleNetworkNative, EntryPoint = "AppleNetNative_NwProcessInputData")]
            internal static partial int ProcessInputData(SafeNetworkFrameworkConnectionHandle connection, SafeNetworkFrameworkFramerHandle framer, byte* buffer, int bufferLength);

            [LibraryImport(Interop.Libraries.AppleNetworkNative, EntryPoint = "AppleNetNative_NwStartTlsHandshake")]
            internal static partial int StartTlsHandshake(SafeNetworkFrameworkConnectionHandle connection, GCHandle handle);

            [LibraryImport(Interop.Libraries.AppleNetworkNative, EntryPoint = "AppleNetNative_NwCancelConnection")]
            internal static partial int CancelConnection(SafeNetworkFrameworkConnectionHandle connection);

            [LibraryImport(Interop.Libraries.AppleNetworkNative, EntryPoint = "AppleNetNative_NwSendToConnection")]
            internal static partial int SendToConnection(SafeNetworkFrameworkConnectionHandle connection, GCHandle handle, byte* buffer, int bufferLength);

            [LibraryImport(Interop.Libraries.AppleNetworkNative, EntryPoint = "AppleNetNative_NwReadFromConnection")]
            internal static partial int ReadFromConnection(SafeNetworkFrameworkConnectionHandle connection, GCHandle handle, byte* buffer, int bufferLength);

            [LibraryImport(Interop.Libraries.AppleNetworkNative, EntryPoint = "AppleNetNative_NwSetTlsOptions")]
            internal static partial int SetTlsOptions(SafeNetworkFrameworkConnectionHandle connection, GCHandle handle, string targetName, byte* alpnBuffer, int alpnLength, ushort minTlsProtocol, ushort maxTlsProtocol);

            [LibraryImport(Interop.Libraries.AppleNetworkNative, EntryPoint = "AppleNetNative_NwGetConnectionInfo")]
            internal static partial int GetConnectionInfo(SafeNetworkFrameworkConnectionHandle connection, out SslProtocols sslProtocol, out TlsCipherSuite cipherSuite, ref byte* negotiatedAlpn, ref int negotiatedAlpnLength);

            [LibraryImport(Interop.Libraries.AppleNetworkNative, EntryPoint = "AppleNetNative_NwCopyCertChain")]
            internal static partial int CopyCertChain(SafeNetworkFrameworkConnectionHandle connection, out SafeCFArrayHandle certChain, out int certChainLength);

            [LibraryImport(Interop.Libraries.AppleNetworkNative, EntryPoint = "AppleNetNative_NwInit")]
            internal static unsafe partial int Init(delegate* unmanaged<IntPtr, PAL_NwStatusUpdates, IntPtr, IntPtr, int> statusCallback, delegate* unmanaged<IntPtr, byte*, void**, int> readCallback, delegate* unmanaged<IntPtr, byte*, void**, int> writeCallback);
        }
    }

    // Supporting types for Network Framework
    internal enum PAL_NwStatusUpdates
    {
        Unknown = 0,
        Connected = 1,
        Disconnected = 2,
        Error = 3,
    }

    internal enum TlsCipherSuite : ushort
    {
        Unknown = 0,
        // Add specific cipher suites as needed
    }

    // Forward declaration for SafeCFArrayHandle - this should be defined elsewhere in the crypto interop
    internal sealed class SafeCFArrayHandle : SafeHandle
    {
        public SafeCFArrayHandle() : base(IntPtr.Zero, true) { }
        public override bool IsInvalid => handle == IntPtr.Zero;
        protected override bool ReleaseHandle() => true; // Will be implemented with CF release
    }
}

namespace System.Net
{
    internal class SafeNetworkFrameworkHandle : SafeHandle
    {
        public SafeNetworkFrameworkHandle()
            : base(IntPtr.Zero, ownsHandle: true)
        {
        }

        public SafeNetworkFrameworkHandle(IntPtr handle)
            : this(handle, ownsHandle: true)
        {
        }

        internal SafeNetworkFrameworkHandle(IntPtr handle, bool ownsHandle)
            : base(handle, ownsHandle)
        {
            if (!IsInvalid)
            {
                Interop.NetworkFramework.Retain(this);
            }
        }

        public override bool IsInvalid => handle == IntPtr.Zero;

        protected override bool ReleaseHandle()
        {
            Interop.NetworkFramework.Release(this);
            return true;
        }
    }

    internal sealed class SafeNetworkFrameworkConnectionHandle : SafeNetworkFrameworkHandle
    {
    }

    internal sealed class SafeNetworkFrameworkFramerHandle : SafeNetworkFrameworkHandle
    {
    }
}