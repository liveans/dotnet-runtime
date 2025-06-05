using System;
using System.Net;

namespace System.Net.Security;

internal sealed class SafeDeleteNwContext : SafeDeleteContext
{
    public static readonly unsafe bool IsNetworkFrameworkSupported = Interop.NetworkFramework.Tls.Init(null, null, null) == 0;

    private SafeNetworkFrameworkConnectionHandle? _connection;
    
    public SafeDeleteNwContext(SslAuthenticationOptions sslAuthenticationOptions)
        : base(IntPtr.Zero)
    {
        _connection = Interop.NetworkFramework.Tls.CreateClientContext();
    }

    protected override bool ReleaseHandle()
    {
        _connection?.Dispose();
        return true;
    }
}