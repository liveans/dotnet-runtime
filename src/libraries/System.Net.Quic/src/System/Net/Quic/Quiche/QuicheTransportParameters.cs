// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Runtime.InteropServices;

namespace System.Net.Quic.Implementations.Quiche
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct QuicheTransportParameters
    {
        /// <summary>
        /// The maximum idle timeout.
        /// </summary>
        public ulong PeerMaxIdleTimeout;
        /// <summary>
        /// The maximum UDP payload size.
        /// </summary>
        public ulong PeerMaxUdpPayloadSize;
        /// <summary>
        /// The initial flow control maximum data for the connection.
        /// </summary>
        public ulong PeerInitialMaxData;
        /// <summary>
        /// The initial flow control maximum data for local bidirectional streams.
        /// </summary>
        public ulong PeerInitialMaxStreamDataBidiLocal;
        /// <summary>
        /// The initial flow control maximum data for remote bidirectional streams.
        /// </summary>
        public ulong PeerInitialMaxStreamDataBidiRemote;
        /// <summary>
        /// The initial flow control maximum data for unidirectional streams.
        /// </summary>
        public ulong PeerInitialMaxStreamDataUni;
        /// <summary>
        /// The initial maximum bidirectional streams.
        /// </summary>
        public ulong PeerInitialMaxStreamsBidi;
        /// <summary>
        /// The initial maximum unidirectional streams.
        /// </summary>
        public ulong PeerInitialMaxStreamsUni;
        /// <summary>
        /// The ACK delay exponent.
        /// </summary>
        public ulong PeerAckDelayExponent;
        /// <summary>
        /// The max ACK delay.
        /// </summary>
        public ulong PeerMaxAckDelay;
        /// <summary>
        /// Whether active migration is disabled.
        /// </summary>
        [MarshalAs(UnmanagedType.U1)] public bool PeerDisableActiveMigration;
        /// <summary>
        /// The active connection ID limit.
        /// </summary>
        public ulong PeerActiveConnIdLimit;
        /// <summary>
        /// DATAGRAM frame extension parameter, if any.
        /// </summary>
        [MarshalAs(UnmanagedType.SysInt)] public long PeerMaxDatagramFrameSize;
    }
}
