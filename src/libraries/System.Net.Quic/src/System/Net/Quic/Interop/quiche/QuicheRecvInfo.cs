// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace System.Net.Quic.System.Net.Quic.Interop.quiche
{
    internal unsafe struct QuicheRecvInfo
    {
        QuicAddr* from;
        uint from_len;

        QuicAddr* to;
        uint to_len;
    }
}
