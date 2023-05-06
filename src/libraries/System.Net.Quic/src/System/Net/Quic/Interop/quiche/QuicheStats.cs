// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace System.Net.Quic.System.Net.Quic.Interop.quiche
{
    internal struct QuicheStats
    {
        nuint Recv;
        nuint Sent;
        nuint Lost;
        nuint Retrans;
        ulong SentBytes;
        ulong RecvBytes;
        ulong LostBytes;
        ulong StreamRetransBytes;
        nuint PathsCount;
        ulong PeerMaxIdleTimeout;
        ulong PeerMaxUdpPayloadSize;
        ulong PeerInitialMaxData;
        ulong PeerInitialMaxStreamDataBidiLocal;
        ulong PeerInitialMaxStreamDataBidiRemote;
        ulong PeerInitialMaxStreamDataUni;
        ulong PeerInitialMaxStreamsBidi;
        ulong PeerInitialMaxStreamsUni;
        ulong PeerAckDelayExponent;
        ulong PeerMaxAckDelay;
        bool PeerDisableActiveMigration;
        ulong PeerActiveConnIdLimit;
        nint PeerMaxDatagramFrameSize;
    }
}
