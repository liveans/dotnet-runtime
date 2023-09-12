// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Runtime.InteropServices;

namespace System.Net.Quic.Implementations.Quiche
{
    [StructLayout(LayoutKind.Sequential)]
    public unsafe struct QuicheSendInfo
    {
        // The remote address the packet was received from
#pragma warning disable CS3003 // Type is not CLS-compliant
        public SystemStructures.SockAddrStorage* from;
        public int fromLen;

        // The local address the packet was received on
        public SystemStructures.SockAddrStorage* to;
        public int toLen;

        public SystemStructures.Timespec at;
#pragma warning restore CS3003 // Type is not CLS-compliant
    }
}
