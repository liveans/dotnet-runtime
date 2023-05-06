// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace System.Net.Quic.System.Net.Quic.Interop.quiche
{
    internal enum QuicheError
    {
        Done = -1,
        BufferTooShort = -2,
        UnknownVersion = -3,
        InvalidFrame = -4,
        InvalidPacket = -5,
        InvalidState = -6,
        InvalidStreamState = -7,
        InvalidTransportParam = -8,
        CryptoFail = -9,
        TlsFail = -10,
        FlowControl = -11,
        StreamLimit = -12,
        FinalSize = -13,
        CongestionControl = -14,
        StreamStopped = -15,
        StreamReset = -16,
        IdLimit = -17,
        OutOfIdentifiers = -18,
        KeyUpdate = -19,
    }
}
