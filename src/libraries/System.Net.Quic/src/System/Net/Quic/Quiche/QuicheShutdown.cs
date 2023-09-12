// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace System.Net.Quic.Implementations.Quiche
{
    /// <summary>
    /// The side of the stream to be shut down.
    /// </summary>
    internal enum QuicheShutdown
    {
        /// <summary>
        /// Stop receiving stream data.
        /// </summary>
        Read = 0,

        /// <summary>
        /// Stop sending stream data.
        /// </summary>
        Write = 1,
    }
}
