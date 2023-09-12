// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace System.Net.Quic.Implementations.Quiche
{
    internal sealed class QuicheRecvInfoLifetime
    {
        private readonly SystemStructures.SockAddr _to;
        private readonly SystemStructures.SockAddr _from;
        private QuicheRecvInfo _recvInfo;
        public unsafe QuicheRecvInfoLifetime(IPEndPoint local, IPEndPoint peer)
        {
            QuicheRecvInfo recvInfo;
            // Lifetime Issue
            _from = QuicheConnection.GetSockAddr(peer);
            _to = QuicheConnection.GetSockAddr(local);
            recvInfo.fromLen = sizeof(SystemStructures.SockAddr);
            recvInfo.toLen = sizeof(SystemStructures.SockAddr);
            fixed (SystemStructures.SockAddr* fromPtr = &_from)
            fixed (SystemStructures.SockAddr* toPtr = &_to)
            {
                recvInfo.from = fromPtr;
                recvInfo.to = toPtr;
            }
            _recvInfo = recvInfo;
        }

        public QuicheRecvInfo GetQuicheRecvInfo()
        {
            return _recvInfo;
        }
    }
}
