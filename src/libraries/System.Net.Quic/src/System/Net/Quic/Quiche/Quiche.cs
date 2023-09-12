// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Collections.Generic;
using System.Text;

namespace System.Net.Quic.Implementations.Quiche
{
    internal sealed class Quiche
    {
        public static string Version { get; private set; }

        public Quiche()
        {
        }

        static Quiche()
        {
            Version = QuicheApi.Version;
        }

        public QuicheHeaderInfo GetHeaderInfo(ReadOnlySpan<byte> buffer, nuint localConnIdLen)
        {
            string scid, dcid, token;
            Span<byte> scidSpan = stackalloc byte[QuicheConstants.MaxConnIdLen];
            Span<byte> dcidSpan = stackalloc byte[QuicheConstants.MaxConnIdLen];
            Span<byte> tokenSpan = stackalloc byte[QuicheConstants.MaxConnIdLen];

            int result = QuicheApi.QuicheHeaderInfo(buffer, (ulong)buffer.Length, localConnIdLen, out var version, out var type, scidSpan, out var scidLen, dcidSpan, out var dcidLen, tokenSpan, out var tokenLen);
            if (result < 0)
            {
                // TODO (aaksoy): Error
                throw new Exception("Error parsing header");
            }

            scid = Encoding.UTF8.GetString(scidSpan[..(int)scidLen]);
            dcid = Encoding.UTF8.GetString(dcidSpan[..(int)dcidLen]);
            token = Encoding.UTF8.GetString(tokenSpan[..(int)tokenLen]);

            return new QuicheHeaderInfo(version, type, scid, dcid, token, (int)scidLen, (int)dcidLen, (int)tokenLen);
        }

        private static unsafe SystemStructures.SockAddr GetSockAddr(IPEndPoint endpoint)
        {
            SystemStructures.SockAddr sockAddr;
            sockAddr.sa_family = (ushort)endpoint.AddressFamily;
            if (!endpoint.Address.TryWriteBytes(new Span<byte>(sockAddr.sa_data, 14), out int _))
            {
                // TODO (aaksoy): Invalid Ip
                throw new Exception("Invalid IP");
            }
            return sockAddr;
        }

        private static unsafe nuint GetLength(int length)
        {
            return (nuint)length;
        }

        public static unsafe QuicheConnection Accept(ReadOnlySpan<byte> sourceConnectionId, ReadOnlySpan<byte> otherDestinationConnectionId, IPEndPoint local, IPEndPoint peer, QuicheConfig config)
        {
            SystemStructures.SockAddr localSockAddr = GetSockAddr(local);
            SystemStructures.SockAddr peerSockAddr = GetSockAddr(peer);

            return new QuicheConnection(QuicheApi.QuicheAccept(sourceConnectionId, (nuint)sourceConnectionId.Length, otherDestinationConnectionId, (nuint)otherDestinationConnectionId.Length, ref localSockAddr, (nuint)sizeof(SystemStructures.SockAddr), ref peerSockAddr, (nuint)sizeof(SystemStructures.SockAddr), config.Handle));
        }
        public static unsafe QuicheConnection Connect(string hostname, ReadOnlySpan<byte> sourceConnectionId, IPEndPoint local, IPEndPoint peer, QuicheConfig config)
        {
            SystemStructures.SockAddr localSockAddr = GetSockAddr(local);
            SystemStructures.SockAddr peerSockAddr = GetSockAddr(peer);

            var handle = QuicheApi.QuicheConnect(hostname, sourceConnectionId, (nuint)sourceConnectionId.Length, ref localSockAddr, (nuint)sizeof(SystemStructures.SockAddr), ref peerSockAddr, (nuint)sizeof(SystemStructures.SockAddr), config.Handle);
            return new QuicheConnection(handle);
        }

        public List<byte> CreateNegotiateVersionPacket(ReadOnlySpan<byte> sourceConnectionId, ReadOnlySpan<byte> destinationConnectionId)
        {
            Span<byte> buffer = stackalloc byte[QuicheConstants.MaxDatagramSize];
            long packetLen = 0;
            packetLen = QuicheApi.QuicheNegotiateVersion(sourceConnectionId, (nuint)sourceConnectionId.Length, destinationConnectionId, (nuint)destinationConnectionId.Length, buffer, (nuint)buffer.Length);
            return new List<byte>(buffer[..(int)packetLen].ToArray());
        }

        public List<byte> CreateRetryPacket(ReadOnlySpan<byte> sourceConnectionId, ReadOnlySpan<byte> destinationConnectionId, ReadOnlySpan<byte> newSourceConnectionId, ReadOnlySpan<byte> token, uint version)
        {
            Span<byte> buffer = stackalloc byte[QuicheConstants.MaxDatagramSize];
            int writtenBytes = (int)QuicheApi.QuicheRetry(
                    sourceConnectionId, GetLength(sourceConnectionId.Length),
                    destinationConnectionId, GetLength(destinationConnectionId.Length),
                    newSourceConnectionId, GetLength(newSourceConnectionId.Length),
                    token, GetLength(token.Length),
                    version, buffer, GetLength(buffer.Length)
                );
            return new(buffer[..writtenBytes].ToArray());
        }

        public static bool CheckVersionSupport(uint version)
        {
            return QuicheApi.QuicheVersionIsSupported(version);
        }
    }
}
