// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace System.Net.Quic.Implementations.Quiche
{
    public class QuicheException : Exception
    {
        public QuicheException(QuicheErrorCode errorCode) : base("")
        {
        }
    }
}
