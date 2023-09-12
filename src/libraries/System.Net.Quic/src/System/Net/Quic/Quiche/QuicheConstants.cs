// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace System.Net.Quic.Implementations.Quiche
{
    internal static class QuicheConstants
    {
        internal static int ProtocolVersion = 0x00000001;
        internal static int MaxConnIdLen = 20;
        internal static int MinClientInitialLen = 1200;
        internal static int MaxDatagramSize = 1350;
    }
}
