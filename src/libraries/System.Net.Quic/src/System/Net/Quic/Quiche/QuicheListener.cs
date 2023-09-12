// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Threading.Tasks;
using System.Net.Sockets;
using System.Threading;

namespace System.Net.Quic.Implementations.Quiche
{
    internal sealed class QuicheListener
    {
        private QuicheConfig _config;
        private Socket _socket;
        // private Func<QuicConnection, SslClientHelloInfo, CancellationToken, ValueTask<QuicServerConnectionOptions>>? _connectionCallback = null;
        private int _pendingConnectionsCapacity;
        public IPEndPoint LocalEndPoint { get; }
        internal static ValueTask<QuicheListener> ListenAsync(QuicListenerOptions options)
        {
            QuicheListener listener = new(options);
            // options.Validate(nameof(options));
            return ValueTask.FromResult(listener);
        }
#pragma warning disable CA1416
        private unsafe QuicheListener(QuicListenerOptions options)
        {
            // Let's create socket listener, bind and listen.
            _socket = new Socket(options.ListenEndPoint.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            _socket.Bind(options.ListenEndPoint);
            _socket.Listen(options.ListenBacklog);

            _pendingConnectionsCapacity = options.ListenBacklog;
            LocalEndPoint = (IPEndPoint)_socket.LocalEndPoint!;
            // Let's set config
            _config = new QuicheConfig();
            _config.SetApplicationProtocols(new(options.ApplicationProtocols.ToArray()));
        }

        public async ValueTask<QuicConnection> AcceptConnectionAsync(CancellationToken cancellationToken = default)
        {
            var connection = await _socket.AcceptAsync(cancellationToken).ConfigureAwait(false);
            ArraySegment<byte> buffer = default;
            var _ = await connection.ReceiveAsync(buffer).ConfigureAwait(false);

            throw new NotImplementedException();
        }
#pragma warning restore CA1416
    }
}
