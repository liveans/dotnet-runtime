// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Runtime.InteropServices;

namespace System.Net.Quic.Implementations.Quiche
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct QuichePathStats
    {
        /// <summary>
        /// The local address used by this path.
        /// </summary>
        public SystemStructures.SockAddrStorage LocalAddr;
        /// <summary>
        /// The local address lenght used by this path.
        /// </summary>
        public int LocalAddrLen;

        /// <summary>
        /// The peer address seen by this path.
        /// </summary>
        public SystemStructures.SockAddrStorage PeerAddr;
        /// <summary>
        /// The peer address length seen by this path.
        /// </summary>
        public int PeerAddrLen;

        /// <summary>
        /// The validation state of the path.
        /// </summary>
        [MarshalAs(UnmanagedType.SysInt)] public long ValidationState;
        /// <summary>
        /// Whether this path is active.
        /// </summary>
        public bool Active;
        /// <summary>
        /// The number of QUIC packets received on this path.
        /// </summary>
        [MarshalAs(UnmanagedType.SysUInt)] public ulong Recv;
        /// <summary>
        /// The number of QUIC packets sent on this path.
        /// </summary>
        [MarshalAs(UnmanagedType.SysUInt)] public ulong Sent;
        /// <summary>
        /// The number of QUIC packets that were lost on this path.
        /// </summary>
        [MarshalAs(UnmanagedType.SysUInt)] public ulong Lost;
        /// <summary>
        /// The number of sent QUIC packets with retransmitted data on this path.
        /// </summary>
        [MarshalAs(UnmanagedType.SysUInt)] public ulong Retrans;
        /// <summary>
        /// The estimated round-trip time of the path (in nanoseconds).
        /// </summary>
        public ulong Rtt;
        /// <summary>
        /// The size of the path's congestion window in bytes.
        /// </summary>
        [MarshalAs(UnmanagedType.SysUInt)] public ulong Cwnd;
        /// <summary>
        /// The number of sent bytes on this path.
        /// </summary>
        public ulong SentBytes;
        /// <summary>
        /// The number of received bytes on this path.
        /// </summary>
        public ulong RecvBytes;
        /// <summary>
        /// The number of bytes lost on this path.
        /// </summary>
        public ulong LostBytes;
        /// <summary>
        /// The number of stream bytes retransmitted on this path.
        /// </summary>
        public ulong StreamRetransBytes;
        /// <summary>
        /// The current PMTU for the path.
        /// </summary>
        [MarshalAs(UnmanagedType.SysUInt)] public ulong Pmtu;
        /// <summary>
        /// The most recent data delivery rate estimate in bytes/s.
        /// </summary>
        public ulong DeliveryRate;
    }
}
