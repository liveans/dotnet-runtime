// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Threading;

namespace System.Net.Quic.Implementations.Quiche
{
    internal sealed class QuicheStream
    {
        private static ulong streamIdCounter;
        private readonly ulong _streamId;
        private readonly QuicheConnection _connection;
        internal ulong StreamId => _streamId;
        internal QuicheConnection Connection => _connection;
        private QuicheConnectionSafeHandle _connHandle => _connection.Handle;
        internal QuicheStream(QuicheConnection connection)
        {
            _streamId = Interlocked.Increment(ref streamIdCounter);
            _connection = connection;
        }

        internal QuicheStream(QuicheConnection connection, ulong streamId)
        {
            _streamId = streamId;
            _connection = connection;
        }

        internal (long, bool) Recv(Span<byte> buffer)
        {
            long writtenBytes = QuicheApi.QuicheConnStreamRecv(_connHandle, _streamId, buffer, (ulong)buffer.Length, out bool finished);
            return (writtenBytes, finished);
        }

        internal long Send(ReadOnlySpan<byte> buffer, bool finished)
        {
            return QuicheApi.QuicheConnStreamSend(_connHandle, _streamId, buffer, (ulong)buffer.Length, finished);
        }

        internal int SetPriority(int priority, bool incremental)
        {
            return QuicheApi.QuicheConnStreamPriority(_connHandle, _streamId, (byte)priority, incremental);
        }

        internal int Shutdown(QuicheShutdown shutdownDirection, QuicheErrorCode errorCode)
        {
            return QuicheApi.QuicheConnStreamShutdown(_connHandle, _streamId, shutdownDirection, (ulong)errorCode);
        }

        internal long GetCapacity()
        {
            return QuicheApi.QuicheConnStreamCapacity(_connHandle, _streamId);
        }

        internal bool IsReadable()
        {
            return QuicheApi.QuicheConnStreamReadable(_connHandle, _streamId);
        }

        internal int IsWritable(int len)
        {
            return QuicheApi.QuicheConnStreamWritable(_connHandle, _streamId, (nuint)len);
        }

        internal bool IsFinished()
        {
            return QuicheApi.QuicheConnStreamFinished(_connHandle, _streamId);
        }
    }
}
