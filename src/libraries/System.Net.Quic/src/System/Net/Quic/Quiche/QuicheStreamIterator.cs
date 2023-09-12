// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Collections.Generic;

namespace System.Net.Quic.Implementations.Quiche
{
    internal sealed class QuicheStreamIterator
    {
        private readonly QuicheStreamIteratorSafeHandle _handle;
        private readonly QuicheConnection _connection;
        internal QuicheStreamIterator(nint handle, QuicheConnection connection)
        {
            _handle = new(handle);
            _connection = connection;
        }

        internal unsafe QuicheStream? Next()
        {
            bool success = QuicheApi.QuicheStreamIterNext(_handle, out ulong streamId);
            return success ? new QuicheStream(_connection, streamId) : null;
        }

        public IEnumerator<QuicheStream> GetEnumerator()
        {
            var next = Next();
            if (next is not null)
            {
                yield return next;
            }
        }
    }
}
