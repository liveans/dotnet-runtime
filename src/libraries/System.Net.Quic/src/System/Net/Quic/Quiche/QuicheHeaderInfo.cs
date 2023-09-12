// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace System.Net.Quic.Implementations.Quiche
{
    internal sealed class QuicheHeaderInfo
    {
        private readonly uint _version;
        private readonly byte _type;
        private readonly string _sourceConnectionId;
        private readonly string _destinationConnectionId;
        private readonly string _token;
        private readonly int _sourceConnectionIdLength;
        private readonly int _destinationConnectionIdLength;
        private readonly int _tokenLength;
        public uint Version => _version;
        public byte Type => _type;
        public string SourceConnectionId => _sourceConnectionId;
        public string DestinationConnectionId => _destinationConnectionId;
        public string Token => _token;
        public int SourceConnectionIdLength => _sourceConnectionIdLength;
        public int DestinationConnectionIdLength => _destinationConnectionIdLength;
        public int TokenLength => _tokenLength;

        internal QuicheHeaderInfo(uint version, byte type, string sourceConnectionId, string destinationConnectionId, string token, int sourceConnectionIdLength, int destinationConnectionIdLength, int tokenLength)
        {
            _version = version;
            _type = type;
            _sourceConnectionId = sourceConnectionId;
            _destinationConnectionId = destinationConnectionId;
            _token = token;
            _sourceConnectionIdLength = sourceConnectionIdLength;
            _destinationConnectionIdLength = destinationConnectionIdLength;
            _tokenLength = tokenLength;
        }
    }
}
