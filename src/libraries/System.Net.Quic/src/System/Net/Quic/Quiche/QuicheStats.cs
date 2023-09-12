// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Runtime.InteropServices;

namespace System.Net.Quic.Implementations.Quiche
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct QuicheStats
    {
        /// <summary>
        /// The number of QUIC packets received on this connection.
        /// </summary>
        [MarshalAs(UnmanagedType.SysUInt)] public ulong Recv;
        /// <summary>
        /// The number of QUIC packets sent on this connection.
        /// </summary>
        [MarshalAs(UnmanagedType.SysUInt)] public ulong Sent;
        /// <summary>
        /// The number of QUIC packets that were lost.
        /// </summary>
        [MarshalAs(UnmanagedType.SysUInt)] public ulong Lost;
        /// <summary>
        /// The number of sent QUIC packets with retransmitted data.
        /// </summary>
        [MarshalAs(UnmanagedType.SysUInt)] public ulong Retrans;
        /// <summary>
        /// The number of sent bytes.
        /// </summary>
        public ulong SentBytes;
        /// <summary>
        /// The number of received bytes.
        /// </summary>
        public ulong RecvBytes;
        /// <summary>
        /// The number of bytes lost.
        /// </summary>
        public ulong LostBytes;
        /// <summary>
        /// The number of stream bytes retransmitted.
        /// </summary>
        public ulong StreamRetransBytes;
        /// <summary>
        /// The number of known paths for the connection.
        /// </summary>
        [MarshalAs(UnmanagedType.SysUInt)] public ulong PathsCount;
    }
}
