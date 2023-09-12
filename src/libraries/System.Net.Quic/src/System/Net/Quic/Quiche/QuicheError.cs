// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace System.Net.Quic.Implementations.Quiche
{
    public enum QuicheErrorCode
    {
        /// <summary>
        /// There is no more work to do.
        /// </summary>
        Done = -1,

        /// <summary>
        /// The provided buffer is too short.
        /// </summary>
        TooShort = -2,

        /// <summary>
        /// The provided packet cannot be parsed because its version is unknown.
        /// </summary>
        UnknownVersion = -3,

        /// <summary>
        /// The provided packet cannot be parsed because it contains an invalid frame.
        /// </summary>
        InvalidFrame = -4,

        /// <summary>
        /// The provided packet cannot be parsed.
        /// </summary>
        InvalidPacket = -5,

        /// <summary>
        /// The operation cannot be completed because the connection is in an invalid state.
        /// </summary>
        InvalidState = -6,

        /// <summary>
        /// The operation cannot be completed because the stream is in an invalid state.
        /// </summary>
        InvalidStreamState = -7,

        /// <summary>
        /// The peer's transport params cannot be parsed.
        /// </summary>
        InvalidTransportParam = -8,

        /// <summary>
        /// A cryptographic operation failed.
        /// </summary>
        CryptoFail = -9,

        /// <summary>
        /// The TLS handshake failed.
        /// </summary>
        TlsFail = -10,

        /// <summary>
        /// The peer violated the local flow control limits.
        /// </summary>
        FlowControl = -11,

        /// <summary>
        /// The peer violated the local stream limits.
        /// </summary>
        StreamLimit = -12,

        /// <summary>
        /// The received data exceeds the stream's final size.
        /// </summary>
        FinalSize = -13,

        /// <summary>
        /// Error in congestion control.
        /// </summary>
        CongestionControl = -14,

        /// <summary>
        /// The specified stream was stopped by the peer.
        /// </summary>
        StreamStopped = -15,

        /// <summary>
        /// The specified stream was reset by the peer.
        /// </summary>
        StreamReset = -16,

        /// <summary>
        /// Too many identifiers were provided.
        /// </summary>
        IdLimit = -17,

        /// <summary>
        /// Not enough available identifiers.
        /// </summary>
        OutOfIdentifiers = -18,

        /// <summary>
        /// Error in key update.
        /// </summary>
        KeyUpdate = -19,
    }

    internal class QuicheGenericError
    {
        public bool IsApplicationError { get; set; }
        public ulong ErrorCode { get; set; }
        public byte[] Reason { get; set; }

        protected QuicheGenericError(bool isApplicationError, ulong errorCode, ReadOnlySpan<byte> reason)
        {
            IsApplicationError = isApplicationError;
            ErrorCode = errorCode;
            Reason = reason.ToArray();
        }
    }

    internal sealed class QuicheApplicationError : QuicheGenericError
    {
        public QuicheApplicationError(ulong errorCode, ReadOnlySpan<byte> reason) : base(true, errorCode, reason)
        {
        }
    }

    internal sealed class QuicheError : QuicheGenericError
    {
        public QuicheError(QuicheErrorCode errorCode, ReadOnlySpan<byte> reason) : base(false, (ulong) errorCode, reason)
        {
        }
    }
}
