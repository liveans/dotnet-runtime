// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Text;
using System.Threading.Tasks;

namespace System.Net.Quic.Implementations.Quiche
{
    public class QuicheConnection : IAsyncDisposable
    {
        private QuicheConnectionSafeHandle _handle;
        internal QuicheConnectionSafeHandle Handle => _handle;

        private SystemStructures.SockAddr _localAddress;
        private SystemStructures.SockAddr _peerAddress;

        internal QuicheConnection(nint handle)
        {
            _handle = new QuicheConnectionSafeHandle(handle);
            bool success = true;
            _handle.DangerousAddRef(ref success);
        }

        internal unsafe QuicheConnection(
            ReadOnlySpan<byte> sourceConnectionId,
            ReadOnlySpan<byte> oDestinationConnectionId,
            IPEndPoint local,
            IPEndPoint peer,
            QuicheConfig config,
            void* ssl,
            bool isServer
        )
        {
            _localAddress = GetSockAddr(local);
            _peerAddress = GetSockAddr(peer);
            _handle = new QuicheConnectionSafeHandle(
                    QuicheApi.QuicheConnNewWithTls(
                        sourceConnectionId, (nuint)sourceConnectionId.Length,
                        oDestinationConnectionId, (nuint)oDestinationConnectionId.Length,
                        ref _localAddress, (nuint)sizeof(SystemStructures.SockAddr),
                        ref _peerAddress, (nuint)sizeof(SystemStructures.SockAddr),
                        config.Handle,
                        ssl,
                        isServer
                )
            );
        }

        public static unsafe SystemStructures.SockAddr GetSockAddr(IPEndPoint endpoint)
        {
            SystemStructures.SockAddr sockAddr;
            sockAddr.sa_family = (ushort)endpoint.AddressFamily;
            if (!endpoint.Address.TryWriteBytes(new Span<byte>(sockAddr.sa_data, 14), out int _))
            {
                // TODO (aaksoy): Invalid Ip
            }
            return sockAddr;
        }

        public unsafe bool SetKeylogPath(string path)
        {
            return QuicheApi.QuicheConnSetKeylogPath(_handle, path);
        }

        public unsafe bool SetQlogPath(string path, string logTitle, string logDesc)
        {
            return QuicheApi.QuicheConnSetQlogPath(_handle, path, logTitle, logDesc);
        }

        public int SetSession(ReadOnlySpan<byte> session)
        {
            return QuicheApi.QuicheConnSetSession(_handle, session, (nuint)session.Length);
        }

        public long Recv(Span<byte> buffer, int dataLen, QuicheRecvInfo recvInfo)
        {
            return QuicheApi.QuicheConnRecv(_handle, buffer, (ulong)dataLen, ref recvInfo);
        }

        public (int, QuicheSendInfo) CreateSendPacket(Span<byte> buffer)
        {
            var writtenBytes = (int)QuicheApi.QuicheConnSend(_handle, buffer, (ulong)buffer.Length, out var sendInfo);
            return (writtenBytes, sendInfo);
        }

        public (int, QuicheSendInfo) CreateSendPacket(byte[] buffer)
        {
            return CreateSendPacket(new Span<byte>(buffer));
        }

        public int SendQuantum()
        {
            return (int)QuicheApi.QuicheConnSendQuantum(_handle);
        }

        internal QuicheStream GetNextReadableStream()
        {
            var streamId = QuicheApi.QuicheConnStreamReadableNext(_handle);
            if (streamId == -1)
            {
                // TODO: Handle no stream available case
            }
            return new QuicheStream(this, (ulong)streamId);
        }

        internal QuicheStream GetNextWritableStream()
        {
            var streamId = QuicheApi.QuicheConnStreamWritableNext(_handle);
            if (streamId == -1)
            {
                // TODO: Handle no stream available case
            }
            return new QuicheStream(this, (ulong)streamId);
        }

        internal QuicheStreamIterator GetReadableStreamsIterator()
        {
            return new(QuicheApi.QuicheConnReadable(_handle), this);
        }

        internal QuicheStreamIterator GetWritableStreamsIterator()
        {
            return new(QuicheApi.QuicheConnWritable(_handle), this);
        }

        internal ulong GetMaxSendUdpPayloadSize()
        {
            return QuicheApi.QuicheConnMaxSendUdpPayloadSize(_handle);
        }

        internal ulong GetTimeoutAsNanos()
        {
            return QuicheApi.QuicheConnTimeoutAsNanos(_handle);
        }

        internal ulong GetTimeoutAsMillis()
        {
            return QuicheApi.QuicheConnTimeoutAsMillis(_handle);
        }

        internal void ProcessTimeoutEvent()
        {
            QuicheApi.QuicheConnOnTimeout(_handle);
        }

        internal int Close(bool isApplicationError, int errorCode, string reason) => Close(isApplicationError, errorCode, Encoding.ASCII.GetBytes(reason));

        internal int Close(bool isApplicationError, int errorCode, ReadOnlySpan<byte> reason)
        {
            return QuicheApi.QuicheConnClose(_handle, isApplicationError, (ulong)errorCode, reason, (ulong)reason.Length);
        }

        internal unsafe ReadOnlySpan<byte> GetTraceId()
        {
            byte* result;
            QuicheApi.QuicheConnTraceId(_handle, &result, out var resultLen);
            return new(result, (int)resultLen);
        }

        internal unsafe ReadOnlySpan<byte> GetSourceId()
        {
            byte* result;
            QuicheApi.QuicheConnSourceId(_handle, &result, out var resultLen);
            return new(result, (int)resultLen);
        }

        internal unsafe ReadOnlySpan<byte> GetDestinationId()
        {
            byte* result;
            QuicheApi.QuicheConnDestinationId(_handle, &result, out var resultLen);
            return new(result, (int)resultLen);
        }

        internal unsafe ReadOnlySpan<byte> GetNegotiatedALPN()
        {
            byte* result;
            QuicheApi.QuicheConnApplicationProto(_handle, &result, out var resultLen);
            return new(result, (int)resultLen);
        }

        internal unsafe ReadOnlySpan<byte> GetPeerCertificate()
        {
            byte* result;
            QuicheApi.QuicheConnPeerCert(_handle, &result, out var resultLen);
            return new(result, (int)resultLen);
        }

        internal unsafe ReadOnlySpan<byte> GetSession()
        {
            byte* result;
            QuicheApi.QuicheConnSession(_handle, &result, out var resultLen);
            return new(result, (int)resultLen);
        }

        internal bool IsEstablished()
        {
            return QuicheApi.QuicheConnIsEstablished(_handle);
        }

        internal bool IsInEarlyData()
        {
            return QuicheApi.QuicheConnIsInEarlyData(_handle);
        }

        internal bool IsReadable()
        {
            return QuicheApi.QuicheConnIsReadable(_handle);
        }

        internal bool IsDraining()
        {
            return QuicheApi.QuicheConnIsDraining(_handle);
        }

        internal ulong GetPeerStreamsLeftBidirectionalCount()
        {
            return QuicheApi.QuicheConnPeerStreamsLeftBidi(_handle);
        }

        internal ulong GetPeerStreamsLeftUnidirectionalCount()
        {
            return QuicheApi.QuicheConnPeerStreamsLeftUni(_handle);
        }

        internal bool IsClosed()
        {
            return QuicheApi.QuicheConnIsClosed(_handle);
        }

        private static QuicheGenericError GenerateError(bool isApp, ulong errorCode, ReadOnlySpan<byte> reason)
        {
            return isApp ? new QuicheApplicationError(errorCode, reason) : new QuicheError((QuicheErrorCode)errorCode, reason);
        }

        internal unsafe QuicheGenericError? ProcessPeerError()
        {
            byte* reason;

            bool success = QuicheApi.QuicheConnPeerError(_handle, out var isApp, out var errorCode, &reason, out var reasonLen);
            return success ? GenerateError(isApp, errorCode, new(reason, (int)reasonLen)) : null;
        }

        internal unsafe QuicheGenericError? ProcessLocalError()
        {
            byte* reason;

            bool success = QuicheApi.QuicheConnLocalError(_handle, out var isApp, out var errorCode, &reason, out var reasonLen);
            return success ? GenerateError(isApp, errorCode, new(reason, (int)reasonLen)) : null;
        }

        internal QuicheStats Stats()
        {
            QuicheApi.QuicheConnStats(_handle, out var stats);
            return stats;
        }

        internal unsafe QuichePathStats PathStats(ulong pathIndex)
        {
            QuicheApi.QuicheConnPathStats(_handle, Convert.ToByte(pathIndex), out var stats);
            return stats;
        }

        internal ValueTask<QuicheDatagram> CreateDatagramAsync()
        {
            return ValueTask.FromResult(new QuicheDatagram(this));
        }

        internal unsafe long ScheduleAckElicitingPacket()
        {
            return QuicheApi.QuicheConnSendAckEliciting(_handle);
        }

        internal unsafe long ScheduleAckElicitingPacket(IPEndPoint local, IPEndPoint peer)
        {
            var localSockAddr = GetSockAddr(local);
            var peerSockAddr = GetSockAddr(peer);
            return QuicheApi.QuicheConnSendAckElicitingOnPath(_handle, ref localSockAddr, (nuint)sizeof(SystemStructures.SockAddr), ref peerSockAddr, (nuint)sizeof(SystemStructures.SockAddr));
        }

        public ValueTask DisposeAsync()
        {
            throw new NotImplementedException();
        }
    }
}
