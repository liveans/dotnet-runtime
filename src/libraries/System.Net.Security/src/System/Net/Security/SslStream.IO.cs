// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Buffers;
using System.Diagnostics;
using System.IO;
using System.Runtime.CompilerServices;
using System.Runtime.ExceptionServices;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace System.Net.Security
{
    public partial class SslStream
    {
        private readonly SslAuthenticationOptions _sslAuthenticationOptions = new SslAuthenticationOptions();
        private NestedState _nestedAuth;
        private bool _isRenego;

        private TlsFrameHelper.TlsFrameInfo _lastFrame;

        private object _handshakeLock => _sslAuthenticationOptions;
        private volatile TaskCompletionSource<bool>? _handshakeWaiter;

        private const int HandshakeTypeOffsetSsl2 = 2;                       // Offset of HelloType in Sslv2 and Unified frames
        private const int HandshakeTypeOffsetTls = 5;                        // Offset of HelloType in Sslv3 and TLS frames

        private const int UnknownTlsFrameLength = int.MaxValue;              // frame too short to determine length

        private bool _receivedEOF;

        private Task<int>? _frameTask;

        // Used by Telemetry to ensure we log connection close exactly once
        private enum ConnectionStatus
        {
            NoHandshake = 0,
            HandshakeCompleted = 1, // connection opened
            Disposed = 2, // connection closed
        }

        private ConnectionStatus _connectionOpenedStatus;

        private void SetException(Exception e)
        {
            Debug.Assert(e != null, $"Expected non-null Exception to be passed to {nameof(SetException)}");

            _exception ??= ExceptionDispatchInfo.Capture(e);

            CloseContext();
        }

        //
        // This is to not depend on GC&SafeHandle class if the context is not needed anymore.
        //
        private void CloseInternal()
        {
            _exception = s_disposedSentinel;
            CloseContext();
            _frameTask?.ContinueWith(t =>
            {
                _ = t.Exception;
                _buffer.ReturnBuffer();
            },
            CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously | TaskContinuationOptions.OnlyOnFaulted, TaskScheduler.Default);
            // Ensure a Read or Auth operation is not in progress,
            // block potential future read and auth operations since SslStream is disposing.
            // This leaves the _nestedRead = StreamDisposed and _nestedAuth = StreamDisposed, but that's ok, since
            // subsequent operations check the _exception sentinel first
            if (Interlocked.Exchange(ref _nestedRead, NestedState.StreamDisposed) == NestedState.StreamNotInUse &&
                Interlocked.Exchange(ref _nestedAuth, NestedState.StreamDisposed) == NestedState.StreamNotInUse && _frameTask == null)
            {
                _buffer.ReturnBuffer();
            }

            if (!_buffer.IsValid)
            {
                // Suppress finalizer since the read buffer was returned.
                GC.SuppressFinalize(this);
            }

            if (NetSecurityTelemetry.Log.IsEnabled())
            {
                // Set the status to disposed. If it was opened before, log ConnectionClosed
                if (Interlocked.Exchange(ref _connectionOpenedStatus, ConnectionStatus.Disposed) == ConnectionStatus.HandshakeCompleted)
                {
                    NetSecurityTelemetry.Log.ConnectionClosed(GetSslProtocolInternal());
                }
            }
        }

        private ProtocolToken EncryptData(ReadOnlyMemory<byte> buffer)
        {
            ThrowIfExceptionalOrNotAuthenticated();

            lock (_handshakeLock)
            {
                if (_handshakeWaiter != null)
                {
                    ProtocolToken token = default;
                    // avoid waiting under lock.
                    token.Status = new SecurityStatusPal(SecurityStatusPalErrorCode.TryAgain);
                    return token;
                }

                return Encrypt(buffer);
            }
        }

        //
        // This method assumes that a SSPI context is already in a good shape.
        // For example it is either a fresh context or already authenticated context that needs renegotiation.
        //
        private Task ProcessAuthenticationAsync(bool isAsync = false, CancellationToken cancellationToken = default)
        {
            ThrowIfExceptional();

            if (NetSecurityTelemetry.AnyTelemetryEnabled())
            {
                return ProcessAuthenticationWithTelemetryAsync(isAsync, cancellationToken);
            }
            else
            {
                return isAsync ?
                    ForceAuthenticationAsync<AsyncReadWriteAdapter>(IsServer, null, cancellationToken) :
                    ForceAuthenticationAsync<SyncReadWriteAdapter>(IsServer, null, cancellationToken);
            }
        }

        private async Task ProcessAuthenticationWithTelemetryAsync(bool isAsync, CancellationToken cancellationToken)
        {
            long startingTimestamp;
            if (NetSecurityTelemetry.Log.IsEnabled())
            {
                NetSecurityTelemetry.Log.HandshakeStart(IsServer, _sslAuthenticationOptions.TargetHost.Replace('\0', ' '));
                startingTimestamp = Stopwatch.GetTimestamp();
            }
            else
            {
                startingTimestamp = 0;
            }

            Activity? activity = NetSecurityTelemetry.StartActivity(this);
            Exception? exception = null;
            try
            {
                Task task = isAsync ?
                    ForceAuthenticationAsync<AsyncReadWriteAdapter>(IsServer, null, cancellationToken) :
                    ForceAuthenticationAsync<SyncReadWriteAdapter>(IsServer, null, cancellationToken);

                await task.ConfigureAwait(false);

                if (startingTimestamp is not 0)
                {
                    // SslStream could already have been disposed at this point, in which case _connectionOpenedStatus == ConnectionStatus.Disposed
                    // Make sure that we increment the open connection counter only if it is guaranteed to be decremented in dispose/finalize
                    bool connectionOpen = Interlocked.CompareExchange(ref _connectionOpenedStatus, ConnectionStatus.HandshakeCompleted, ConnectionStatus.NoHandshake) == ConnectionStatus.NoHandshake;
                    SslProtocols protocol = GetSslProtocolInternal();
                    NetSecurityTelemetry.Log.HandshakeCompleted(protocol, startingTimestamp, connectionOpen);
                }
            }
            catch (Exception ex)
            {
                exception = ex;
                if (startingTimestamp is not 0)
                {
                    NetSecurityTelemetry.Log.HandshakeFailed(IsServer, startingTimestamp, ex.Message);
                }

                throw;
            }
            finally
            {
                NetSecurityTelemetry.StopActivity(activity, exception, this);
            }
        }

        //
        // This is used to reply on re-handshake when received SEC_I_RENEGOTIATE on Read().
        //
        private async Task ReplyOnReAuthenticationAsync<TIOAdapter>(byte[]? buffer, CancellationToken cancellationToken)
            where TIOAdapter : IReadWriteAdapter
        {
            try
            {
                await ForceAuthenticationAsync<TIOAdapter>(receiveFirst: false, buffer, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                _handshakeWaiter!.SetResult(true);
                _handshakeWaiter = null;
            }
        }

        // This will initiate renegotiation or PHA for Tls1.3
        private async Task RenegotiateAsync<TIOAdapter>(CancellationToken cancellationToken)
            where TIOAdapter : IReadWriteAdapter
        {
            if (Interlocked.CompareExchange(ref _nestedAuth, NestedState.StreamInUse, NestedState.StreamNotInUse) != NestedState.StreamNotInUse)
            {
                ObjectDisposedException.ThrowIf(_nestedAuth == NestedState.StreamDisposed, this);
                throw new InvalidOperationException(SR.Format(SR.net_io_invalidnestedcall, "authenticate"));
            }

            if (Interlocked.CompareExchange(ref _nestedRead, NestedState.StreamInUse, NestedState.StreamNotInUse) != NestedState.StreamNotInUse)
            {
                ObjectDisposedException.ThrowIf(_nestedRead == NestedState.StreamDisposed, this);
                throw new NotSupportedException(SR.Format(SR.net_io_invalidnestedcall, "read"));
            }

            // Write is different since we do not do anything special in Dispose
            if (Interlocked.Exchange(ref _nestedWrite, NestedState.StreamInUse) != NestedState.StreamNotInUse)
            {
                _nestedRead = NestedState.StreamNotInUse;
                throw new NotSupportedException(SR.Format(SR.net_io_invalidnestedcall, "write"));
            }

            ProtocolToken token = default;
            token.RentBuffer = true;
            try
            {
                if (_buffer.ActiveLength > 0)
                {
                    throw new InvalidOperationException(SR.net_ssl_renegotiate_buffer);
                }

                _sslAuthenticationOptions.RemoteCertRequired = true;
                _isRenego = true;


                token = Renegotiate();

                if (token.Size > 0)
                {
                    await TIOAdapter.WriteAsync(InnerStream, token.AsMemory(), cancellationToken).ConfigureAwait(false);
                    await TIOAdapter.FlushAsync(InnerStream, cancellationToken).ConfigureAwait(false);
                }

                token.ReleasePayload();

                if (token.Status.ErrorCode != SecurityStatusPalErrorCode.OK)
                {
                    if (token.Status.ErrorCode == SecurityStatusPalErrorCode.NoRenegotiation)
                    {
                        // Peer does not want to renegotiate. That should keep session usable.
                        return;
                    }

                    throw SslStreamPal.GetException(token.Status);
                }

                do
                {
                    int frameSize = await ReceiveHandshakeFrameAsync<TIOAdapter>(cancellationToken).ConfigureAwait(false);
                    token = ProcessTlsFrame(frameSize);

                    if (token.Size > 0)
                    {
                        await TIOAdapter.WriteAsync(InnerStream, token.AsMemory(), cancellationToken).ConfigureAwait(false);
                        await TIOAdapter.FlushAsync(InnerStream, cancellationToken).ConfigureAwait(false);
                    }
                    token.ReleasePayload();
                }
                while (token.Status.ErrorCode == SecurityStatusPalErrorCode.ContinueNeeded);

                CompleteHandshake(_sslAuthenticationOptions);
            }
            finally
            {
                if (_buffer.ActiveLength == 0)
                {
                    _buffer.ReturnBuffer();
                }

                token.ReleasePayload();

                _nestedRead = NestedState.StreamNotInUse;
                _nestedWrite = NestedState.StreamNotInUse;
                _isRenego = false;
                // We will not release _nestedAuth at this point to prevent another renegotiation attempt.
            }
        }

        // reAuthenticationData is only used on Windows in case of renegotiation.
        private async Task ForceAuthenticationAsync<TIOAdapter>(bool receiveFirst, byte[]? reAuthenticationData, CancellationToken cancellationToken)
            where TIOAdapter : IReadWriteAdapter
        {
            if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, $"Starting authentication - receiveFirst: {receiveFirst}, isServer: {IsServer}", "ForceAuthenticationAsync");
            bool isSync = typeof(TIOAdapter) == typeof(SyncReadWriteAdapter);
            bool handshakeCompleted = false;
            ProtocolToken token = default;
            Task<SecurityStatusPalErrorCode>? handshakeTask = null;

            token.RentBuffer = true;

            if (reAuthenticationData == null)
            {
                // prevent nesting only when authentication functions are called explicitly. e.g. handle renegotiation transparently.
                if (Interlocked.Exchange(ref _nestedAuth, NestedState.StreamInUse) == NestedState.StreamInUse)
                {
                    throw new InvalidOperationException(SR.Format(SR.net_io_invalidnestedcall, "authenticate"));
                }
            }
            try
            {
                if (!receiveFirst)
                {
                    if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, "Calling NextMessage to initiate handshake", "ForceAuthenticationAsync");
                    token = NextMessage(reAuthenticationData, out int consumed);
                    Debug.Assert(consumed == (reAuthenticationData?.Length ?? 0));

                    if (token.Size > 0)
                    {
                        if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, $"Sending handshake data - size: {token.Size}", "ForceAuthenticationAsync");
                        Debug.Assert(token.Payload != null);
                        await TIOAdapter.WriteAsync(InnerStream, new ReadOnlyMemory<byte>(token.Payload!, 0, token.Size), cancellationToken).ConfigureAwait(false);
                        await TIOAdapter.FlushAsync(InnerStream, cancellationToken).ConfigureAwait(false);
                        if (NetEventSource.Log.IsEnabled())
                            NetEventSource.Log.SentFrame(this, token.Payload);
                    }

                    token.ReleasePayload();

                    if (token.Failed)
                    {
                        if (NetEventSource.Log.IsEnabled()) NetEventSource.Error(this, $"Initial handshake failed - status: {token.Status}", "ForceAuthenticationAsync");
                        // tracing done in NextMessage()
                        throw new AuthenticationException(SR.net_auth_SSPI, token.GetException());
                    }
                    else if (token.Status.ErrorCode == SecurityStatusPalErrorCode.OK)
                    {
                        if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, "Handshake completed in first step", "ForceAuthenticationAsync");
                        // We can finish renegotiation without doing any read.
                        handshakeCompleted = true;
                    }
                    else if (token.Status.ErrorCode == SecurityStatusPalErrorCode.ContinuePending)
                    {
                        if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, "Handshake requires async continuation", "ForceAuthenticationAsync");
                        // TODO: Propagate cancellationToken to handshakeTask
                        // Only extract handshake task for contexts that support async operations
                        if (SslStreamPal.SupportsAsyncOperations(_securityContext))
                        {
                            handshakeTask = SslStreamPal.ExtractHandshakeTask(_credentialsHandle!, _securityContext!);
                        }
                    }
                }
                if (!handshakeCompleted)
                {
                    if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, "Ensuring buffer space for handshake", "ForceAuthenticationAsync");
                    _buffer.EnsureAvailableSpace(InitialHandshakeBufferSize);
                }

                int frameSize = 0;
                while (!handshakeCompleted)
                {
                    if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, $"Handshake loop iteration - handshakeTask: {handshakeTask != null}", "ForceAuthenticationAsync");
                    if (handshakeTask != null)
                    {
                        if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, "Processing async handshake task", "ForceAuthenticationAsync");
                        if (_lastFrame.Header.Type == TlsContentType.Alert)
                        {
                            if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, "Processing TLS alert during handshake", "ForceAuthenticationAsync");
                            // This is optimization to consume and report alters instead of throwing IO exception as
                            // the peer would typically close connection afterwards.
                            // We don't want to throw here, that would be done later if needed.
                            // We wait for the task to complete, but ignore any exception,
                            // as it will be handled when we check task status.
                            try
                            {
                                if (isSync)
                                {
                                    if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, "Waiting on handshakeTask (alert).", "ForceAuthenticationAsync");
                                    handshakeTask.Wait(cancellationToken);
                                    if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, "Waiting on handshakeTask (alert) completed.", "ForceAuthenticationAsync");
                                }
                                else
                                {
                                    if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, "Waiting on handshakeTask (alert) async.", "ForceAuthenticationAsync");
                                    await handshakeTask.WaitAsync(cancellationToken).ConfigureAwait(false);
                                    if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, "Waiting on handshakeTask (alert) async completed.", "ForceAuthenticationAsync");
                                }
                            }
                            catch (OperationCanceledException)
                            {
                                // If the token was cancelled, we should stop and re-throw.
                                throw;
                            }
                            catch
                            {
                                // This is expected if the handshake task failed on its own.
                                // We'll handle the faulted state below.
                            }
                        }
                        else
                        {
                            if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, "Setting up frame task for handshake", "ForceAuthenticationAsync");
                            if (isSync)
                            {
                                _frameTask ??= Task<int>.Run(() =>
                                {
                                    ValueTask<int> vt = ReceiveHandshakeFrameAsync<TIOAdapter>(cancellationToken);
                                    Debug.Assert(vt.IsCompleted, "Sync operation must have completed synchronously");
                                    return vt.GetAwaiter().GetResult();
                                }, cancellationToken);
                            }
                            else
                            {
                                _frameTask ??= ReceiveHandshakeFrameAsync<TIOAdapter>(cancellationToken).AsTask();
                            }

                            if (isSync)
                            {
                                if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, "Waiting on handshakeTask or frameTask.", "ForceAuthenticationAsync");
                                _ = Task.WaitAny(new Task[] { handshakeTask, _frameTask },
                                    cancellationToken);
                                if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, $"WaitAny handshakeTask:{handshakeTask.IsCompleted} frameTask:{_frameTask.IsCompleted}", "ForceAuthenticationAsync");
                            }
                            else
                            {
                                if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, "Waiting on handshakeTask or frameTask async.", "ForceAuthenticationAsync");
                                await Task.WhenAny(handshakeTask, _frameTask).WaitAsync(cancellationToken).ConfigureAwait(false);
                                if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, $"WhenAny handshakeTask:{handshakeTask.IsCompleted} frameTask:{_frameTask.IsCompleted}", "ForceAuthenticationAsync");
                            }
                        }
                        if (handshakeTask.IsCompleted)
                        {
                            if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, $"Handshake task completed - IsFaulted: {handshakeTask.IsFaulted}", "ForceAuthenticationAsync");
                            if (handshakeTask.IsFaulted)
                            {
                                token.Status = new SecurityStatusPal(SecurityStatusPalErrorCode.InternalError, handshakeTask.Exception);
                            }
                            else
                            {
                                token.Status = new SecurityStatusPal(handshakeTask.Result);
                            }

                            // Only call GetPendingWriteData for contexts that support async operations
                            if (SslStreamPal.SupportsAsyncOperations(_securityContext))
                            {
                                SslStreamPal.GetPendingWriteData(_securityContext!, ref token);
                            }

                            handshakeTask = null;

                            if (token.Status.ErrorCode == SecurityStatusPalErrorCode.OK)
                            {
                                if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, $"Handshake completed successfully - Context type: {_securityContext?.GetType().Name}, will call CompleteHandshake for certificate validation", "ForceAuthenticationAsync");
                                // handshake completed successfully, but we still need certificate validation
                                // handshakeCompleted = true;
                                break;
                            }
                            else if (token.Status.ErrorCode == SecurityStatusPalErrorCode.ContinuePending)
                            {
                                if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, "Handshake needs more processing", "ForceAuthenticationAsync");
                                // Only extract handshake task for contexts that support async operations
                                if (SslStreamPal.SupportsAsyncOperations(_securityContext))
                                {
                                    handshakeTask = SslStreamPal.ExtractHandshakeTask(_credentialsHandle!, _securityContext!);
                                }
                            }

                            if (token.Size > 0)
                            {
                                // If there is message send it out even if call failed. It may contain TLS Alert.
                                await TIOAdapter.WriteAsync(InnerStream, token.AsMemory(), cancellationToken).ConfigureAwait(false);
                                await TIOAdapter.FlushAsync(InnerStream, cancellationToken).ConfigureAwait(false);

                                if (NetEventSource.Log.IsEnabled())
                                    NetEventSource.Log.SentFrame(this, token.AsMemory().Span);
                            }

                            token.ReleasePayload();

                            if (token.Failed)
                            {
                                if (NetEventSource.Log.IsEnabled()) NetEventSource.Error(this, token.Status, "ForceAuthenticationAsync");

                                if (_lastFrame.Header.Type == TlsContentType.Alert && _lastFrame.AlertDescription != TlsAlertDescription.CloseNotify &&
                                    token.Status.ErrorCode == SecurityStatusPalErrorCode.IllegalMessage)
                                {
                                    // Improve generic message and show details if we failed because of TLS Alert.
                                    throw new AuthenticationException(SR.Format(SR.net_auth_tls_alert, _lastFrame.AlertDescription.ToString()), token.GetException());
                                }

                                throw new AuthenticationException(SR.net_auth_SSPI, token.GetException());
                            }

                            continue;
                        }
                    }
                    if (_frameTask != null)
                    {
                        if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, "Processing frame task", "ForceAuthenticationAsync");
                        frameSize = await _frameTask.ConfigureAwait(false);
                        _frameTask = null;
                    }
                    else
                    {
                        if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, "Receiving handshake frame", "ForceAuthenticationAsync");
                        frameSize = await ReceiveHandshakeFrameAsync<TIOAdapter>(cancellationToken).ConfigureAwait(false);
                    }

                    if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, $"Processing TLS frame - size: {frameSize}", "ForceAuthenticationAsync");
                    token = ProcessTlsFrame(frameSize);

                    ReadOnlyMemory<byte> payload = default;
                    if (token.Size > 0)
                    {
                        payload = token.AsMemory();
                    }
                    else if (token.Failed && (_lastFrame.Header.Type == TlsContentType.Handshake || _lastFrame.Header.Type == TlsContentType.ChangeCipherSpec))
                    {
                        // If we failed without OS sending out alert, inject one here to be consistent across platforms.
                        payload = TlsFrameHelper.CreateAlertFrame(_lastFrame.Header.Version, TlsAlertDescription.ProtocolVersion);
                    }

                    if (!payload.IsEmpty)
                    {
                        // If there is message send it out even if call failed. It may contain TLS Alert.
                        await TIOAdapter.WriteAsync(InnerStream, payload, cancellationToken).ConfigureAwait(false);
                        await TIOAdapter.FlushAsync(InnerStream, cancellationToken).ConfigureAwait(false);

                        if (NetEventSource.Log.IsEnabled())
                            NetEventSource.Log.SentFrame(this, payload.Span);
                    }

                    token.ReleasePayload();

                    if (token.Failed)
                    {
                        if (NetEventSource.Log.IsEnabled()) NetEventSource.Error(this, token.Status, "ForceAuthenticationAsync");

                        if (_lastFrame.Header.Type == TlsContentType.Alert && _lastFrame.AlertDescription != TlsAlertDescription.CloseNotify &&
                                 token.Status.ErrorCode == SecurityStatusPalErrorCode.IllegalMessage)
                        {
                            // Improve generic message and show details if we failed because of TLS Alert.
                            throw new AuthenticationException(SR.Format(SR.net_auth_tls_alert, _lastFrame.AlertDescription.ToString()), token.GetException());
                        }

                        throw new AuthenticationException(SR.net_auth_SSPI, token.GetException());
                    }
                    else if (token.Status.ErrorCode == SecurityStatusPalErrorCode.OK)
                    {
                        // We can finish renegotiation without doing any read.
                        handshakeCompleted = true;
                    }
                }

                if (NetEventSource.Log.IsEnabled())
                    NetEventSource.Info(this, $"About to call CompleteHandshake - handshakeCompleted: {handshakeCompleted}, Context type: {_securityContext?.GetType().Name}");

                CompleteHandshake(_sslAuthenticationOptions);

                if (NetEventSource.Log.IsEnabled())
                    NetEventSource.Info(this, "CompleteHandshake finished successfully");
            }
            finally
            {
                if (reAuthenticationData == null)
                {
                    _nestedAuth = NestedState.StreamNotInUse;
                    _isRenego = false;
                }

                token.ReleasePayload();

                // reset the cached flag which has potentially outdated value.
                _localClientCertificateUsed = -1;
            }

#pragma warning disable SYSLIB0058 // Use NegotiatedCipherSuite.
            if (NetEventSource.Log.IsEnabled())
                NetEventSource.Log.SspiSelectedCipherSuite(nameof(ForceAuthenticationAsync),
                                                                    SslProtocol,
                                                                    CipherAlgorithm,
                                                                    CipherStrength,
                                                                    HashAlgorithm,
                                                                    HashStrength,
                                                                    KeyExchangeAlgorithm,
                                                                    KeyExchangeStrength);
#pragma warning restore SYSLIB0058 // Use NegotiatedCipherSuite.
        }

        // This method will make sure we have at least one full TLS frame buffered.
        private async ValueTask<int> ReceiveHandshakeFrameAsync<TIOAdapter>(CancellationToken cancellationToken)
            where TIOAdapter : IReadWriteAdapter
        {
            if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, "Starting to receive handshake frame", "ReceiveHandshakeFrameAsync");
            int frameSize = await EnsureFullTlsFrameAsync<TIOAdapter>(cancellationToken, InitialHandshakeBufferSize).ConfigureAwait(false);
            if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, $"EnsureFullTlsFrameAsync returned frameSize: {frameSize}", "ReceiveHandshakeFrameAsync");

            if (frameSize == 0)
            {
                if (NetEventSource.Log.IsEnabled()) NetEventSource.Error(this, "Frame size is 0, throwing EOF exception", "ReceiveHandshakeFrameAsync");
                // We expect to receive at least one frame
                throw new IOException(SR.net_io_eof);
            }

            // At this point, we have at least one TLS frame.
            if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, $"Processing TLS frame - Type: {_lastFrame.Header.Type}", "ReceiveHandshakeFrameAsync");
            switch (_lastFrame.Header.Type)
            {
                case TlsContentType.Alert:
                    if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, "Processing TLS Alert frame", "ReceiveHandshakeFrameAsync");
                    if (TlsFrameHelper.TryGetFrameInfo(_buffer.EncryptedReadOnlySpan, ref _lastFrame))
                    {
                        if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, $"Alert Description: {_lastFrame.AlertDescription}", "ReceiveHandshakeFrameAsync");
                        if (NetEventSource.Log.IsEnabled() && _lastFrame.AlertDescription != TlsAlertDescription.CloseNotify) NetEventSource.Error(this, $"Received TLS alert {_lastFrame.AlertDescription}");
                    }
                    break;
                case TlsContentType.Handshake:
                    if (NetEventSource.Log.IsEnabled())
                    {
                        TlsHandshakeType handshakeType = (TlsHandshakeType)0;
                        if (_buffer.EncryptedLength > TlsFrameHelper.HeaderSize)
                        {
                            handshakeType = (TlsHandshakeType)_buffer.EncryptedReadOnlySpan[TlsFrameHelper.HeaderSize];
                        }
                        NetEventSource.Info(this, $"Processing first handshake frame in buffer. Type: {handshakeType}", "ReceiveHandshakeFrameAsync");
                    }
#pragma warning disable CS0618
                    if (!_isRenego && _buffer.EncryptedReadOnlySpan[_lastFrame.Header.Version == SslProtocols.Ssl2 ? HandshakeTypeOffsetSsl2 : HandshakeTypeOffsetTls] == (byte)TlsHandshakeType.ClientHello &&
                        _sslAuthenticationOptions!.IsServer) // guard against malicious endpoints. We should not see ClientHello on client.
#pragma warning restore CS0618
                    {
                        TlsFrameHelper.ProcessingOptions options = NetEventSource.Log.IsEnabled() ?
                                                                    TlsFrameHelper.ProcessingOptions.All :
                                                                    TlsFrameHelper.ProcessingOptions.ServerName;
                        if (OperatingSystem.IsMacOS() && _sslAuthenticationOptions.IsServer)
                        {
                            // macOS cannot process ALPN on server at the moment.
                            // We fallback to our own process similar to SNI bellow.
                            options |= TlsFrameHelper.ProcessingOptions.RawApplicationProtocol;
                        }

                        // Process SNI from Client Hello message
                        if (!TlsFrameHelper.TryGetFrameInfo(_buffer.EncryptedReadOnlySpan, ref _lastFrame, options))
                        {
                            if (NetEventSource.Log.IsEnabled()) NetEventSource.Error(this, $"Failed to parse TLS hello.", "ReceiveHandshakeFrameAsync");
                        }

                        if (_lastFrame.HandshakeType == TlsHandshakeType.ClientHello)
                        {
                            // SNI if it exist. Even if we could not parse the hello, we can fall-back to default certificate.
                            if (_lastFrame.TargetName != null)
                            {
                                _sslAuthenticationOptions.TargetHost = _lastFrame.TargetName;
                            }

                            if (_sslAuthenticationOptions.ServerOptionDelegate != null)
                            {
                                SslServerAuthenticationOptions userOptions =
                                    await _sslAuthenticationOptions.ServerOptionDelegate(this, new SslClientHelloInfo(_sslAuthenticationOptions.TargetHost, _lastFrame.SupportedVersions),
                                        _sslAuthenticationOptions.UserState, cancellationToken).ConfigureAwait(false);
                                _sslAuthenticationOptions.UpdateOptions(userOptions);
                            }
                        }

                        if (NetEventSource.Log.IsEnabled())
                        {
                            NetEventSource.Log.ReceivedFrame(this, _lastFrame);
                        }
                    }
                    break;
                case TlsContentType.AppData:
                    if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, "Processing TLS AppData frame", "ReceiveHandshakeFrameAsync");
                    // TLS1.3 it is not possible to distinguish between late Handshake and Application Data
                    // In TLS 1.3, encrypted handshake messages appear as AppData frames and must be processed
                    // by the TLS implementation during handshake to complete key derivation and handshake state
                    if (_isRenego && SslProtocol != SslProtocols.Tls13)
                    {
                        if (NetEventSource.Log.IsEnabled()) NetEventSource.Error(this, "Invalid AppData during renegotiation (not TLS 1.3)", "ReceiveHandshakeFrameAsync");
                        throw new InvalidOperationException(SR.net_ssl_renegotiate_data);
                    }
                    if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, "TLS 1.3 encrypted handshake data - will be processed by TLS stack", "ReceiveHandshakeFrameAsync");
                    break;

            }

            if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, $"Returning frameSize: {frameSize}", "ReceiveHandshakeFrameAsync");
            return frameSize;
        }

        // Calls crypto on received data. No IO inside.
        private ProtocolToken ProcessTlsFrame(int frameSize)
        {
            int chunkSize = frameSize;

            ReadOnlySpan<byte> availableData = _buffer.EncryptedReadOnlySpan;

            // Often more TLS messages fit into same packet. Get as many complete frames as we can.
            while (_buffer.EncryptedLength - chunkSize > TlsFrameHelper.HeaderSize)
            {
                TlsFrameHeader nextHeader = default;

                if (!TlsFrameHelper.TryGetFrameHeader(availableData.Slice(chunkSize), ref nextHeader))
                {
                    break;
                }

                if (NetEventSource.Log.IsEnabled())
                {
                    string subType = "";
                    if (nextHeader.Type == TlsContentType.Handshake && availableData.Length > chunkSize + TlsFrameHelper.HeaderSize)
                    {
                        subType = $" ({(TlsHandshakeType)availableData[chunkSize + TlsFrameHelper.HeaderSize]})";
                    }
                    NetEventSource.Info(this, $"Bundling frame. Type: {nextHeader.Type}{subType} Length: {nextHeader.Length}", nameof(ProcessTlsFrame));
                }

                frameSize = nextHeader.Length;

                // Can process more handshake frames in single step or during TLS1.3 post-handshake auth, but we should
                // avoid processing too much so as to preserve API boundary between handshake and I/O.
                if ((nextHeader.Type != TlsContentType.Handshake && nextHeader.Type != TlsContentType.ChangeCipherSpec) && !_isRenego || frameSize > availableData.Length - chunkSize)
                {
                    // We don't have full frame left or we already have app data which needs to be processed by decrypt.
                    break;
                }

                chunkSize += frameSize;
            }

            ProtocolToken token = NextMessage(availableData.Slice(0, chunkSize), out int consumed);
            _buffer.DiscardEncrypted(consumed);
            return token;
        }

        //
        //  This is to reset auth state on remote side.
        //  If this write succeeds we will allow auth retrying.
        //
        private void SendAuthResetSignal(ReadOnlySpan<byte> alert, ExceptionDispatchInfo exception)
        {
            SetException(exception.SourceException);

            if (alert.Length == 0)
            {
                //
                // We don't have an alert to send so cannot retry and fail prematurely.
                //
                exception.Throw();
            }

            InnerStream.Write(alert);

            exception.Throw();
        }

        // - Loads the channel parameters
        // - Optionally verifies the Remote Certificate
        // - Sets HandshakeCompleted flag
        // - Sets the guarding event if other thread is waiting for
        //   handshake completion
        //
        // - Returns false if failed to verify the Remote Cert
        //
        private bool CompleteHandshake(ref ProtocolToken alertToken, out SslPolicyErrors sslPolicyErrors, out X509ChainStatusFlags chainStatus)
        {
            if (NetEventSource.Log.IsEnabled())
                NetEventSource.Info(this, $"CompleteHandshake called - Context type: {_securityContext?.GetType().Name}, NestedAuth: {_nestedAuth}");

            ProcessHandshakeSuccess();

            // Reset the frame task after handshake to ensure subsequent reads create fresh tasks
            _frameTask = null;

            if (_nestedAuth != NestedState.StreamInUse)
            {
                if (NetEventSource.Log.IsEnabled()) NetEventSource.Error(this, $"Ignoring unsolicited renegotiated certificate.", "CompleteHandshake");
                // ignore certificates received outside of handshake or requested renegotiation.
                sslPolicyErrors = SslPolicyErrors.None;
                chainStatus = X509ChainStatusFlags.NoError;
                return true;
            }

#if TARGET_ANDROID
            // On Android, the remote certificate verification can be invoked from Java TrustManager's callback
            // during the handshake process. If that has occurred, we shouldn't run the validation again and
            // return the existing validation result.
            //
            // The Java TrustManager callback is called only when the peer has a certificate. It's possible that
            // the peer didn't provide any certificate (for example when the peer is the client) and the validation
            // result hasn't been set. In that case we still need to run the verification at this point.
            if (TryGetRemoteCertificateValidationResult(out sslPolicyErrors, out chainStatus, ref alertToken, out bool isValid))
            {
                _handshakeCompleted = isValid;
                return isValid;
            }
#endif

            if (NetEventSource.Log.IsEnabled())
                NetEventSource.Info(this, $"About to call VerifyRemoteCertificate (line 736) - Context type: {_securityContext?.GetType().Name}");

            if (!VerifyRemoteCertificate(_sslAuthenticationOptions.CertValidationDelegate, _sslAuthenticationOptions.CertificateContext?.Trust, ref alertToken, out sslPolicyErrors, out chainStatus))
            {
                if (NetEventSource.Log.IsEnabled())
                    NetEventSource.Error(this, "VerifyRemoteCertificate failed - handshake will fail");
                _handshakeCompleted = false;
                return false;
            }

            if (NetEventSource.Log.IsEnabled())
                NetEventSource.Info(this, $"VerifyRemoteCertificate succeeded - sslPolicyErrors: {sslPolicyErrors}");

            _handshakeCompleted = true;
            return true;
        }

        private void CompleteHandshake(SslAuthenticationOptions sslAuthenticationOptions)
        {
            if (NetEventSource.Log.IsEnabled())
                NetEventSource.Info(this, $"CompleteHandshake(SslAuthenticationOptions) called - about to call main CompleteHandshake method");

            ProtocolToken alertToken = default;
            if (!CompleteHandshake(ref alertToken, out SslPolicyErrors sslPolicyErrors, out X509ChainStatusFlags chainStatus))
            {
                if (sslAuthenticationOptions!.CertValidationDelegate != null)
                {
                    // there may be some chain errors but the decision was made by custom callback. Details should be tracing if enabled.
                    SendAuthResetSignal(new ReadOnlySpan<byte>(alertToken.Payload), ExceptionDispatchInfo.Capture(new AuthenticationException(SR.net_ssl_io_cert_custom_validation, null)));
                }
                else if (sslPolicyErrors == SslPolicyErrors.RemoteCertificateChainErrors && chainStatus != X509ChainStatusFlags.NoError)
                {
                    // We failed only because of chain and we have some insight.
                    SendAuthResetSignal(new ReadOnlySpan<byte>(alertToken.Payload), ExceptionDispatchInfo.Capture(new AuthenticationException(SR.Format(SR.net_ssl_io_cert_chain_validation, chainStatus), null)));
                }
                else
                {
                    // Simple add sslPolicyErrors as crude info.
                    SendAuthResetSignal(new ReadOnlySpan<byte>(alertToken.Payload), ExceptionDispatchInfo.Capture(new AuthenticationException(SR.Format(SR.net_ssl_io_cert_validation, sslPolicyErrors), null)));
                }
            }

            // Ensure frameTask is reset here as well, in case the protected CompleteHandshake method wasn't called
            _frameTask = null;
        }

        private async ValueTask WriteAsyncChunked<TIOAdapter>(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken)
            where TIOAdapter : IReadWriteAdapter
        {
            do
            {
                int chunkBytes = Math.Min(buffer.Length, MaxDataSize);
                await WriteSingleChunk<TIOAdapter>(buffer.Slice(0, chunkBytes), cancellationToken).ConfigureAwait(false);
                buffer = buffer.Slice(chunkBytes);
            } while (buffer.Length != 0);
        }

        private ValueTask WriteSingleChunk<TIOAdapter>(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken)
            where TIOAdapter : IReadWriteAdapter
        {
            ProtocolToken token;
            while (true)
            {
                token = EncryptData(buffer);
                // TryAgain should be rare, when renegotiation happens exactly when we want to write.
                if (token.Status.ErrorCode != SecurityStatusPalErrorCode.TryAgain)
                {
                    break;
                }

                // We failed to encrypt because renegotiation is pending.
                TaskCompletionSource<bool>? waiter = _handshakeWaiter;
                if (waiter != null)
                {
                    Task waiterTask = TIOAdapter.WaitAsync(waiter);
                    // We finished synchronously waiting for renegotiation. We can try again immediately.
                    if (waiterTask.IsCompletedSuccessfully)
                    {
                        continue;
                    }

                    // We need to wait asynchronously as well as for the write when EncryptData is finished.
                    return WaitAndWriteAsync(buffer, waiterTask, cancellationToken);
                }
            }

            if (token.Status.ErrorCode != SecurityStatusPalErrorCode.OK)
            {
                token.ReleasePayload();
                return ValueTask.FromException(ExceptionDispatchInfo.SetCurrentStackTrace(new IOException(SR.net_io_encrypt, SslStreamPal.GetException(token.Status))));
            }

            ValueTask t = TIOAdapter.WriteAsync(InnerStream, token.AsMemory(), cancellationToken);
            if (t.IsCompletedSuccessfully)
            {
                token.ReleasePayload();
                return t;
            }
            else
            {
                return CompleteWriteAsync(t, token);
            }

            async ValueTask WaitAndWriteAsync(ReadOnlyMemory<byte> buffer, Task waitTask, CancellationToken cancellationToken)
            {
                ProtocolToken token = default;
                try
                {
                    // Wait for renegotiation to finish.
                    await waitTask.ConfigureAwait(false);

                    token = EncryptData(buffer);
                    if (token.Status.ErrorCode == SecurityStatusPalErrorCode.TryAgain)
                    {
                        // Call WriteSingleChunk() recursively to avoid code duplication.
                        // This should be extremely rare in cases when second renegotiation happens concurrently with Write.
                        await WriteSingleChunk<TIOAdapter>(buffer, cancellationToken).ConfigureAwait(false);
                    }
                    else if (token.Status.ErrorCode == SecurityStatusPalErrorCode.OK)
                    {
                        await TIOAdapter.WriteAsync(InnerStream, token.AsMemory(), cancellationToken).ConfigureAwait(false);
                    }
                    else
                    {
                        throw new IOException(SR.net_io_encrypt, SslStreamPal.GetException(token.Status));
                    }
                }
                finally
                {
                    token.ReleasePayload();
                }
            }

            static async ValueTask CompleteWriteAsync(ValueTask writeTask, ProtocolToken token)
            {
                try
                {
                    await writeTask.ConfigureAwait(false);
                }
                finally
                {
                    token.ReleasePayload();
                }
            }
        }

        ~SslStream()
        {
            Dispose(disposing: false);
        }

        private void ReturnReadBufferIfEmpty()
        {
            if (_buffer.ActiveLength == 0)
            {
                _buffer.ReturnBuffer();
            }
        }

        private bool HaveFullTlsFrame(out int frameSize)
        {
            frameSize = GetFrameSize(_buffer.EncryptedReadOnlySpan);
            return _buffer.EncryptedLength >= frameSize;
        }

        [AsyncMethodBuilder(typeof(PoolingAsyncValueTaskMethodBuilder<>))]
        private async ValueTask<int> EnsureFullTlsFrameAsync<TIOAdapter>(CancellationToken cancellationToken, int estimatedSize)
            where TIOAdapter : IReadWriteAdapter
        {
            if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, $"Starting - estimatedSize: {estimatedSize}", "EnsureFullTlsFrameAsync");
            if (HaveFullTlsFrame(out int frameSize))
            {
                if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, $"Already have full TLS frame - frameSize: {frameSize}", "EnsureFullTlsFrameAsync");
                return frameSize;
            }

            if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, "Don't have full frame, reading from stream", "EnsureFullTlsFrameAsync");
            await TIOAdapter.ReadAsync(InnerStream, Memory<byte>.Empty, cancellationToken).ConfigureAwait(false);
            if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, "Initial ReadAsync completed", "EnsureFullTlsFrameAsync");

            // If we don't have enough data to determine the frame size, use the provided estimate
            // (e.g. a full TLS frame for reads, and a somewhat shorter frame for handshake / renegotiation).
            // If we do know the frame size, ensure we have space for the whole frame.
            int spaceNeeded = frameSize == UnknownTlsFrameLength ? estimatedSize : frameSize - _buffer.EncryptedLength;
            if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, $"Ensuring available space: {spaceNeeded} bytes", "EnsureFullTlsFrameAsync");
            _buffer.EnsureAvailableSpace(spaceNeeded);

            if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, $"Starting read loop - current encrypted length: {_buffer.EncryptedLength}, target frameSize: {frameSize}", "EnsureFullTlsFrameAsync");
            while (_buffer.EncryptedLength < frameSize)
            {
                // there should be space left to read into
                Debug.Assert(_buffer.AvailableLength > 0, "_buffer.AvailableBytes > 0");
                if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, $"Reading more data - available buffer space: {_buffer.AvailableLength}", "EnsureFullTlsFrameAsync");

                // We either don't have full frame or we don't have enough data to even determine the size.
                int bytesRead = await TIOAdapter.ReadAsync(InnerStream, _buffer.AvailableMemory, cancellationToken).ConfigureAwait(false);
                if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, $"Read {bytesRead} bytes from stream", "EnsureFullTlsFrameAsync");
                if (bytesRead == 0)
                {
                    if (_buffer.EncryptedLength != 0)
                    {
                        if (NetEventSource.Log.IsEnabled()) NetEventSource.Error(this, $"EOF in middle of TLS frame - encrypted length: {_buffer.EncryptedLength}", "EnsureFullTlsFrameAsync");
                        // we got EOF in middle of TLS frame. Treat that as error.
                        throw new IOException(SR.net_io_eof);
                    }

                    if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, "EOF with no data, returning 0", "EnsureFullTlsFrameAsync");
                    return 0;
                }

                _buffer.Commit(bytesRead);
                if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, $"Committed {bytesRead} bytes, total encrypted length: {_buffer.EncryptedLength}", "EnsureFullTlsFrameAsync");

                if (frameSize == int.MaxValue && _buffer.EncryptedLength > TlsFrameHelper.HeaderSize)
                {
                    if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, "Recalculating frame size", "EnsureFullTlsFrameAsync");
                    // recalculate frame size if needed e.g. we could not get it before.
                    frameSize = GetFrameSize(_buffer.EncryptedReadOnlySpan);
                    if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, $"New frameSize: {frameSize}", "EnsureFullTlsFrameAsync");
                    _buffer.EnsureAvailableSpace(frameSize - _buffer.EncryptedLength);
                }
            }

            if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, $"Completed - returning frameSize: {frameSize}", "EnsureFullTlsFrameAsync");
            return frameSize;
        }

        private SecurityStatusPal DecryptData(int frameSize)
        {
            SecurityStatusPal status;

            lock (_handshakeLock)
            {
                ThrowIfExceptionalOrNotAuthenticated();

                // Decrypt will decrypt in-place and modify these to point to the actual decrypted data, which may be smaller.
                status = Decrypt(_buffer.EncryptedSpanSliced(frameSize), out int decryptedOffset, out int decryptedCount);
                if (status.ErrorCode == SecurityStatusPalErrorCode.ContinuePending)
                {
                    _buffer.DiscardEncrypted(frameSize);
                    return status;
                }
                _buffer.OnDecrypted(decryptedOffset, decryptedCount, frameSize);

                if (status.ErrorCode == SecurityStatusPalErrorCode.Renegotiate)
                {
                    // The status indicates that peer wants to renegotiate. (Windows only)
                    // In practice, there can be some other reasons too - like TLS1.3 session creation
                    // of alert handling. We need to pass the data to lsass and it is not safe to do parallel
                    // write any more as that can change TLS state and the EncryptData() can fail in strange ways.

                    // To handle this we call DecryptData() under lock and we create TCS waiter.
                    // EncryptData() checks that under same lock and if it exist it will not call low-level crypto.
                    // Instead it will wait synchronously or asynchronously and it will try again after the wait.
                    // The result will be set when ReplyOnReAuthenticationAsync() is finished e.g. lsass business is over.
                    // If that happen before EncryptData() runs, _handshakeWaiter will be set to null
                    // and EncryptData() will work normally e.g. no waiting, just exclusion with DecryptData()

                    if (_sslAuthenticationOptions.AllowRenegotiation || SslProtocol == SslProtocols.Tls13 || _nestedAuth != NestedState.StreamNotInUse)
                    {
                        // create TCS only if we plan to proceed. If not, we will throw later outside of the lock.
                        // Tls1.3 does not have renegotiation. However on Windows this error code is used
                        // for session management e.g. anything lsass needs to see.
                        // We also allow it when explicitly requested using RenegotiateAsync().
                        _handshakeWaiter = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
                    }
                }
            }

            return status;
        }

        [AsyncMethodBuilder(typeof(PoolingAsyncValueTaskMethodBuilder<>))]
        private async ValueTask<int> ReadAsyncInternal<TIOAdapter>(Memory<byte> buffer, CancellationToken cancellationToken)
            where TIOAdapter : IReadWriteAdapter
        {
            if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, $"Starting - buffer length: {buffer.Length}", "ReadAsyncInternal");
            bool isSync = typeof(TIOAdapter) == typeof(SyncReadWriteAdapter);
            if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, $"isSync: {isSync}", "ReadAsyncInternal");
            Debug.Assert(_securityContext != null, "Security context must be initialized before ReadAsyncInternal is called.");
            // Throw first if we already have exception.
            // Check for disposal is not atomic so we will check again below.
            ThrowIfExceptionalOrNotAuthenticated();

            if (Interlocked.CompareExchange(ref _nestedRead, NestedState.StreamInUse, NestedState.StreamNotInUse) != NestedState.StreamNotInUse)
            {
                ObjectDisposedException.ThrowIf(_nestedRead == NestedState.StreamDisposed, this);
                throw new NotSupportedException(SR.Format(SR.net_io_invalidnestedcall, "read"));
            }

            try
            {
                if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, "Starting read operation", "ReadAsyncInternal");
                int processedLength = 0;
                int nextTlsFrameLength = UnknownTlsFrameLength;

                if (_buffer.DecryptedLength != 0)
                {
                    if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, $"Have decrypted data available: {_buffer.DecryptedLength} bytes", "ReadAsyncInternal");
                    processedLength = CopyDecryptedData(buffer);
                    if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, $"Copied {processedLength} bytes from decrypted buffer", "ReadAsyncInternal");
                    if (processedLength == buffer.Length || !HaveFullTlsFrame(out nextTlsFrameLength))
                    {
                        if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, "Returning early - buffer filled or no full TLS frame", "ReadAsyncInternal");
                        // We either filled whole buffer or used all buffered frames.
                        return processedLength;
                    }

                    buffer = buffer.Slice(processedLength);
                    if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, $"Sliced buffer, new length: {buffer.Length}", "ReadAsyncInternal");
                }

                if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, "Checking SslStreamPal for available decrypted bytes", "ReadAsyncInternal");

                // Only call GetAvailableDecryptedBytes for SafeDeleteNwContext
                int availableBytes = 0;
                if (SslStreamPal.SupportsAsyncOperations(_securityContext))
                {
                    availableBytes = SslStreamPal.GetAvailableDecryptedBytes(_securityContext!);
                }

                if (availableBytes > 0)
                {
                    if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, "Reading available decrypted bytes from SslStreamPal", "ReadAsyncInternal");
                    int length = SslStreamPal.ReadDecryptedData(_securityContext, buffer.Span);
                    if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, $"Read {length} bytes from SslStreamPal, returning", "ReadAsyncInternal");
                    return length;
                }
                else if (availableBytes < 0)
                {
                    if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, "SslStreamPal indicates EOF", "ReadAsyncInternal");
                    _receivedEOF = true;
                }

                if (_receivedEOF && nextTlsFrameLength == UnknownTlsFrameLength &&
                        (!SslStreamPal.UseAsyncDecrypt || availableBytes < 0))
                {
                    if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, "EOF condition met, returning 0", "ReadAsyncInternal");
                    // there should be no frames waiting for processing
                    Debug.Assert(_buffer.EncryptedLength == 0);
                    // We received EOF during previous read but had buffered data to return.
                    return 0;
                }

                Debug.Assert(_buffer.DecryptedLength == 0);
                Task<SecurityStatusPalErrorCode>? decryptTask = null;
                if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, $"UseAsyncDecrypt: {SslStreamPal.UseAsyncDecrypt}", "ReadAsyncInternal");
#pragma warning disable CS0162      // Warning on platform where const UseAsyncDecrypt is false
                if (SslStreamPal.UseAsyncDecrypt && SslStreamPal.SupportsAsyncOperations(_securityContext))
                {
                    if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, "Extracting decryption task", "ReadAsyncInternal");
                    cancellationToken.ThrowIfCancellationRequested();
                    decryptTask = SslStreamPal.ExtractDecryptionTask(_securityContext!);
                    if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, $"DecryptTask extracted: {decryptTask != null}", "ReadAsyncInternal");
                }
#pragma warning restore CS0162

                if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, "Starting main read loop", "ReadAsyncInternal");
                while (true)
                {
                    if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, $"Read loop iteration - decryptTask: {decryptTask != null}", "ReadAsyncInternal");
                    int payloadBytes = 0;

                    if (decryptTask != null)
                    {
                        if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, "Processing decrypt task path", "ReadAsyncInternal");
                        if (!_receivedEOF && _frameTask == null)
                        {
                            if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, "Creating new frame task", "ReadAsyncInternal");
                            if (isSync)
                            {
                                _frameTask = Task<int>.Run(() =>
                                {
                                    if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, "Running sync frame task", "ReadAsyncInternal");
                                    ValueTask<int> vt = EnsureFullTlsFrameAsync<TIOAdapter>(cancellationToken, ReadBufferSize);
                                    Debug.Assert(vt.IsCompleted, "Sync operation must have completed synchronously");
                                    return vt.GetAwaiter().GetResult();
                                });
                            }
                            else
                            {
                                _frameTask = EnsureFullTlsFrameAsync<TIOAdapter>(cancellationToken, ReadBufferSize).AsTask();
                            }
                            if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, $"Frame task created: {_frameTask != null}", "ReadAsyncInternal");
                        }

                        if (_frameTask == null)
                        {
                            // We received EOF and we are only waiting for previous dectrypt to finish
                            if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, "Waiting for decrypt task only (no frame task - EOF)", "ReadAsyncInternal");
                            decryptTask.Wait(cancellationToken);
                            if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, "Decrypt task wait completed", "ReadAsyncInternal");
                        }
                        else if (isSync)
                        {
                            if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, "Waiting for either decrypt or frame task (sync)", "ReadAsyncInternal");
                            Task[] tasks = new Task[] { decryptTask, _frameTask };
                            int index = Task.WaitAny(tasks, cancellationToken);
                            if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, $"WaitAny completed - index: {index}", "ReadAsyncInternal");
                        }
                        else
                        {
                            if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, "Waiting for either decrypt or frame task (async)", "ReadAsyncInternal");
                            await Task.WhenAny(_frameTask, decryptTask).ConfigureAwait(false);
                            if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, $"WhenAny completed - frameTaskCompleted: {_frameTask.IsCompleted}, decryptTaskCompleted: {decryptTask.IsCompleted}", "ReadAsyncInternal");
                        }
                        if (decryptTask.IsCompleted)
                        {
                            if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, "Decrypt task completed path", "ReadAsyncInternal");
                            int length = 0;
                            // Only call ReadDecryptedData for contexts that support async operations
                            if (SslStreamPal.SupportsAsyncOperations(_securityContext))
                            {
                                length = SslStreamPal.ReadDecryptedData(_securityContext!, buffer.Span);
                                if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, $"ReadDecryptedData returned {length} bytes", "ReadAsyncInternal");

                                if (SslStreamPal.GetAvailableDecryptedBytes(_securityContext!) < 0)
                                {
                                    _receivedEOF = true;
                                    if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, "Received EOF from SslStreamPal", "ReadAsyncInternal");
                                }
                            }

                            if (length == 0 && buffer.Length > 0 && SslStreamPal.SupportsAsyncOperations(_securityContext) && SslStreamPal.GetAvailableDecryptedBytes(_securityContext!) >= 0)
                            {
                                // Only extract decryption task for contexts that support async operations
                                if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, "No data ready, extracting new decrypt task", "ReadAsyncInternal");
                                if (SslStreamPal.SupportsAsyncOperations(_securityContext))
                                {
                                    decryptTask = SslStreamPal.ExtractDecryptionTask(_securityContext!);
                                }
                                if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, "Continuing loop with new decrypt task", "ReadAsyncInternal");
                                continue;
                            }

                            if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, $"Returning data from decrypt task path: {length} bytes", "ReadAsyncInternal");
                            return length;
                        }
                    }

                    if (_frameTask != null)
                    {
                        if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, "Frame task ready path", "ReadAsyncInternal");
                        try
                        {
                            if (isSync)
                            {
                                if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, "Waiting for frame task synchronously", "ReadAsyncInternal");
                                _frameTask.Wait(cancellationToken);
                                payloadBytes = _frameTask.Result;
                                if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, $"Frame task completed synchronously with {payloadBytes} bytes", "ReadAsyncInternal");
                            }
                            else
                            {
                                if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, "Waiting for frame task asynchronously", "ReadAsyncInternal");
                                payloadBytes = await _frameTask.ConfigureAwait(false);
                                if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, $"Frame task completed asynchronously with {payloadBytes} bytes", "ReadAsyncInternal");
                            }
                        }
                        finally
                        {
                            _frameTask = null;
                        }
                    }
                    else
                    {
                        if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, "No existing frame task, calling EnsureFullTlsFrameAsync", "ReadAsyncInternal");
                        payloadBytes = await EnsureFullTlsFrameAsync<TIOAdapter>(cancellationToken, ReadBufferSize).ConfigureAwait(false);
                        if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, $"EnsureFullTlsFrameAsync returned {payloadBytes} bytes", "ReadAsyncInternal");
                    }

                    if (payloadBytes == 0)
                    {
                        _receivedEOF = true;
                        if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, "Received EOF (payloadBytes == 0)", "ReadAsyncInternal");
                        if (decryptTask != null)
                        {
                            // if we have decrypt pending east EOF and submit it to TLS
                            if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, "Handling EOF with pending decrypt task", "ReadAsyncInternal");
                            SslStreamPal.DecryptMessage(_securityContext, Span<byte>.Empty, out int _1, out int _2);
                            if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, "Continuing loop after EOF handling", "ReadAsyncInternal");
                            continue;
                        }
                        if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, "Breaking loop due to EOF", "ReadAsyncInternal");
                        break;
                    }

                    if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, $"Decrypting data - payloadBytes: {payloadBytes}", "ReadAsyncInternal");
                    SecurityStatusPal status = DecryptData(payloadBytes);
                    if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, $"Decrypt status: {status.ErrorCode}", "ReadAsyncInternal");
                    if (status.ErrorCode == SecurityStatusPalErrorCode.ContinuePending)
                    {
                        // Only extract decryption task for contexts that support async operations
                        if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, "ContinuePending status, extracting decrypt task", "ReadAsyncInternal");
                        if (SslStreamPal.SupportsAsyncOperations(_securityContext))
                        {
                            decryptTask = SslStreamPal.ExtractDecryptionTask(_securityContext!);
                        }
                        if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, "Continuing loop with new decrypt task from ContinuePending", "ReadAsyncInternal");
                        continue;
                    }
                    if (status.ErrorCode != SecurityStatusPalErrorCode.OK)
                    {
                        if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, $"Handling non-OK status: {status.ErrorCode}", "ReadAsyncInternal");
                        byte[]? extraBuffer = null;
                        if (_buffer.DecryptedLength != 0)
                        {
                            if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, $"Preserving decrypted buffer - length: {_buffer.DecryptedLength}", "ReadAsyncInternal");
                            extraBuffer = new byte[_buffer.DecryptedLength];
                            _buffer.DecryptedSpan.CopyTo(extraBuffer);

                            _buffer.Discard(_buffer.DecryptedLength);
                        }

                        if (NetEventSource.Log.IsEnabled())
                            NetEventSource.Info(null, $"***Processing an error Status = {status}", "ReadAsyncInternal");

                        if (status.ErrorCode == SecurityStatusPalErrorCode.Renegotiate)
                        {
                            // We determined above that we will not process it.
                            if (_handshakeWaiter == null)
                            {
                                if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, "Renegotiate with no handshake waiter, throwing", "ReadAsyncInternal");
                                throw new IOException(SR.net_ssl_io_renego);
                            }
                            if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, "Handling renegotiation", "ReadAsyncInternal");
                            await ReplyOnReAuthenticationAsync<TIOAdapter>(extraBuffer, cancellationToken).ConfigureAwait(false);
                            if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, "Renegotiation completed", "ReadAsyncInternal");
                        }
                        else if (status.ErrorCode == SecurityStatusPalErrorCode.ContextExpired)
                        {
                            _receivedEOF = true;
                            if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, "Context expired, breaking loop", "ReadAsyncInternal");
                            break;
                        }
                        else
                        {
                            if (NetEventSource.Log.IsEnabled()) NetEventSource.Error(this, $"Error during decrypt: {status.ErrorCode}", "ReadAsyncInternal");
                            throw new IOException(SR.net_io_decrypt, SslStreamPal.GetException(status));
                        }
                    }

                    if (_buffer.DecryptedLength > 0)
                    {
                        // This will either copy data from rented buffer or adjust final buffer as needed.
                        // In both cases _decryptedBytesOffset and _decryptedBytesCount will be updated as needed.
                        if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, $"Copying decrypted data - length: {_buffer.DecryptedLength}", "ReadAsyncInternal");
                        int copyLength = CopyDecryptedData(buffer);
                        processedLength += copyLength;
                        if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, $"Copied {copyLength} bytes, total processed: {processedLength}", "ReadAsyncInternal");
                        if (copyLength == buffer.Length)
                        {
                            // We have more decrypted data after we filled provided buffer.
                            if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, "Buffer filled, breaking loop", "ReadAsyncInternal");
                            break;
                        }

                        buffer = buffer.Slice(copyLength);
                        if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, $"Sliced buffer, new length: {buffer.Length}", "ReadAsyncInternal");
                    }

                    // Only check for available decrypted bytes for contexts that support async operations
                    if (SslStreamPal.SupportsAsyncOperations(_securityContext) && SslStreamPal.GetAvailableDecryptedBytes(_securityContext!) > 0)
                    {
                        if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, "Reading available decrypted bytes from context", "ReadAsyncInternal");
                        int copyLength = SslStreamPal.ReadDecryptedData(_securityContext!, buffer.Span);
                        processedLength += copyLength;
                        if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, $"Read {copyLength} bytes from context, total processed: {processedLength}", "ReadAsyncInternal");

                        if (copyLength == buffer.Length)
                        {
                            // We have more decrypted data after we filled provided buffer.
                            if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, "Buffer filled from context data, breaking loop", "ReadAsyncInternal");
                            break;
                        }

                        buffer = buffer.Slice(copyLength);
                        if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, $"Sliced buffer after context read, new length: {buffer.Length}", "ReadAsyncInternal");
                        break;
                    }

                    if (processedLength == 0)
                    {
                        // We did not get any real data so far.
                        if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, "No data processed yet, continuing loop", "ReadAsyncInternal");
                        continue;
                    }

                    if (!HaveFullTlsFrame(out payloadBytes))
                    {
                        // We don't have another frame to process but we have some data to return to caller.
                        if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, "No full TLS frame available, breaking loop", "ReadAsyncInternal");
                        break;
                    }

                    TlsFrameHelper.TryGetFrameHeader(_buffer.EncryptedReadOnlySpan, ref _lastFrame.Header);
                    if (_lastFrame.Header.Type != TlsContentType.AppData)
                    {
                        // Alerts, handshake and anything else will be processed separately.
                        // This may not be necessary but it improves compatibility with older versions.
                        if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, $"Non-AppData frame type: {_lastFrame.Header.Type}, breaking loop", "ReadAsyncInternal");
                        break;
                    }
                }

                if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, $"Exiting ReadAsyncInternal - returning {processedLength} bytes", "ReadAsyncInternal");
                return processedLength;
            }
            catch (Exception e)
            {
                if (NetEventSource.Log.IsEnabled()) NetEventSource.Error(this, $"Exception in ReadAsyncInternal: {e}", "ReadAsyncInternal");
                if (e is IOException || (e is OperationCanceledException && cancellationToken.IsCancellationRequested))
                {
                    throw;
                }

                throw new IOException(SR.net_io_read, e);
            }
            finally
            {
                ReturnReadBufferIfEmpty();
                _nestedRead = NestedState.StreamNotInUse;
            }
        }

        private async ValueTask WriteAsyncInternal<TIOAdapter>(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken)
            where TIOAdapter : IReadWriteAdapter
        {
            ThrowIfExceptionalOrNotAuthenticatedOrShutdown();

            if (buffer.Length == 0 && !SslStreamPal.CanEncryptEmptyMessage)
            {
                // If it's an empty message and the PAL doesn't support that, we're done.
                return;
            }

            if (Interlocked.Exchange(ref _nestedWrite, NestedState.StreamInUse) == NestedState.StreamInUse)
            {
                throw new NotSupportedException(SR.Format(SR.net_io_invalidnestedcall, "write"));
            }

            try
            {
                ValueTask t = buffer.Length < MaxDataSize ?
                    WriteSingleChunk<TIOAdapter>(buffer, cancellationToken) :
                    WriteAsyncChunked<TIOAdapter>(buffer, cancellationToken);
                await t.ConfigureAwait(false);
            }
            catch (Exception e)
            {
                if (e is IOException || (e is OperationCanceledException && cancellationToken.IsCancellationRequested))
                {
                    throw;
                }

                throw new IOException(SR.net_io_write, e);
            }
            finally
            {
                _nestedWrite = NestedState.StreamNotInUse;
            }
        }

        private int CopyDecryptedData(Memory<byte> buffer)
        {
            Debug.Assert(_buffer.DecryptedLength > 0);

            int copyBytes = Math.Min(_buffer.DecryptedLength, buffer.Length);
            if (copyBytes != 0)
            {
                _buffer.DecryptedReadOnlySpanSliced(copyBytes).CopyTo(buffer.Span);
                _buffer.Discard(copyBytes);
            }

            return copyBytes;
        }

        // Returns TLS Frame size including header size.
        private int GetFrameSize(ReadOnlySpan<byte> buffer)
        {
            if (buffer.Length < TlsFrameHelper.HeaderSize)
            {
                return UnknownTlsFrameLength;
            }

            if (!TlsFrameHelper.TryGetFrameHeader(buffer, ref _lastFrame.Header))
            {
                throw new IOException(SR.net_ssl_io_frame);
            }

            if (_lastFrame.Header.Length < 0)
            {
                if (NetEventSource.Log.IsEnabled()) NetEventSource.Error(this, "invalid TLS frame size", "GetFrameSize");
                throw new AuthenticationException(SR.net_frame_read_size);
            }

            return _lastFrame.Header.Length;
        }
    }
}
