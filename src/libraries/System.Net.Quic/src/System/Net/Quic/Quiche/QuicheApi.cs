// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Runtime.InteropServices;

using QuicheConnPtr = nint;
using QuicheConfigPtr = nint;
using QuicheStreamIterPtr = nint;
using SizeT = nuint;
using SignedSizeT = nint;
using System.Runtime.CompilerServices;
using System.Text;

namespace System.Net.Quic.Implementations.Quiche
{
    internal sealed unsafe partial class QuicheApi
    {
        private const string QuicheLibraryName = "quiche";

        #region Config APIs

        /*
         * C API:
         * // Returns a human readable string with the quiche version number.
         * const char *quiche_version(void);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Version)]
        private static partial byte* QuicheVersion();
        internal static string Version => Encoding.UTF8.GetString(MemoryMarshal.CreateReadOnlySpanFromNullTerminated(QuicheVersion()));

        /*
         * C API:
         * // Enables logging. |cb| will be called with log messages
         * int quiche_enable_debug_logging(void (*cb)(const char *line, void *argp),
         *                      void *argp);
         */
        //[LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.EnableDebugLogging)]

        //internal static partial int QuicheEnableDebugLogging([MarshalAs(UnmanagedType.FunctionPtr)] QuicheLogCallback logCallback, void* argp);
        //internal delegate void QuicheLogCallback([MarshalAs(UnmanagedType.LPStr)] string line, void* argp);

        /*
         * C API:
         * // Creates a config object with the given version.
         * quiche_config *quiche_config_new(uint32_t version);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Config.ConfigurationNew)]

        internal static partial QuicheConfigPtr QuicheConfigNew(uint version);

        /*
         * C API:
         * // Configures the given certificate chain.
         * int quiche_config_load_cert_chain_from_pem_file(quiche_config *config,
         *                                      const char *path);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Config.LoadCertChainFromPemFile)]

        internal static partial int QuicheConfigLoadCertChainFromPemFile(SafeHandle configHandle, [MarshalAs(UnmanagedType.LPStr)] string path);

        /*
         * C API:
         * // Configures the given private key.
         * int quiche_config_load_priv_key_from_pem_file(quiche_config *config,
         *                                    const char *path);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Config.LoadPrivKeyFromPemFile)]

        internal static partial int QuicheConfigLoadPrivKeyFromPemFile(SafeHandle configHandle, [MarshalAs(UnmanagedType.LPStr)] string path);

        /*
         * C API:
         * // Specifies a file where trusted CA certificates are stored for the purposes of certificate verification.
         * int quiche_config_load_verify_locations_from_file(quiche_config *config,
         *                                        const char *path);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Config.LoadVerifyLocationsFromFile)]

        internal static partial int QuicheConfigLoadVerifyLocationsFromFile(SafeHandle configHandle, [MarshalAs(UnmanagedType.LPStr)] string path);

        /*
         * C API:
         * // Specifies a directory where trusted CA certificates are stored for the purposes of certificate verification.
         * int quiche_config_load_verify_locations_from_directory(quiche_config *config,
         *                                             const char *path);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Config.LoadVerifyLocationsFromDirectory)]

        internal static partial int QuicheConfigLoadVerifyLocationsFromDirectory(SafeHandle configHandle, [MarshalAs(UnmanagedType.LPStr)] string path);

        /*
         * C API:
         * // Configures whether to verify the peer's certificate.
         * void quiche_config_verify_peer(quiche_config *config, bool v);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Config.VerifyPeer)]

        internal static partial void QuicheConfigVerifyPeer(SafeHandle configHandle, [MarshalAs(UnmanagedType.U1)] bool verifyPeer);

        /*
         * C API:
         * // Configures whether to send GREASE.
         * void quiche_config_grease(quiche_config *config, bool v);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Config.Grease)]

        internal static partial void QuicheConfigGrease(SafeHandle configHandle, [MarshalAs(UnmanagedType.U1)] bool grease);

        /*
         * C API:
         * // Enables logging of secrets.
         * void quiche_config_log_keys(quiche_config *config);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Config.LogKeys)]

        internal static partial void QuicheConfigLogKeys(SafeHandle configHandle);

        /*
         * C API:
         * // Enables sending or receiving early data.
         * void quiche_config_enable_early_data(quiche_config *config);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Config.EnableEarlyData)]

        internal static partial void QuicheConfigEnableEarlyData(SafeHandle configHandle);

        /*
         * C API:
         * // Configures the list of supported application protocols.
         * int quiche_config_set_application_protos(quiche_config *config,
         *                               const uint8_t *protos,
         *                               size_t protos_len);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Config.SetApplicationProtocols)]

        internal static partial int QuicheConfigSetApplicationProtocols(SafeHandle configHandle, ReadOnlySpan<byte> protos, SizeT protosLen);

        /*
         * C API:
         * // Sets the `max_idle_timeout` transport parameter, in milliseconds, default is
         * // no timeout.
         * void quiche_config_set_max_idle_timeout(quiche_config *config, uint64_t v);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Config.SetMaxIdleTimeout)]

        internal static partial void QuicheConfigSetMaxIdleTimeout(SafeHandle configHandle, ulong timeout);

        /*
         * C API:
         * // Sets the `max_udp_payload_size transport` parameter.
         * void quiche_config_set_max_recv_udp_payload_size(quiche_config *config, size_t v);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Config.SetMaxRecvUdpPayloadSize)]

        internal static partial void QuicheConfigSetMaxRecvUdpPayloadSize(SafeHandle configHandle, SizeT size);

        /*
         * C API:
         * // Sets the maximum outgoing UDP payload size.
         * void quiche_config_set_max_send_udp_payload_size(quiche_config *config, size_t v);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Config.SetMaxSendUdpPayloadSize)]


        internal static partial void QuicheConfigSetMaxSendUdpPayloadSize(SafeHandle configHandle, SizeT size);

        /*
         * C API:
         * // Sets the `initial_max_data` transport parameter.
         * void quiche_config_set_initial_max_data(quiche_config *config, uint64_t v);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Config.SetInitialMaxData)]

        internal static partial void QuicheConfigSetInitialMaxData(SafeHandle configHandle, ulong v);

        /*
         * C API:
         * // Sets the `initial_max_stream_data_bidi_local` transport parameter.
         * void quiche_config_set_initial_max_stream_data_bidi_local(quiche_config *config, uint64_t v);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Config.SetInitialMaxStreamDataBidiLocal)]

        internal static partial void QuicheConfigSetInitialMaxStreamDataBidiLocal(SafeHandle configHandle, ulong v);

        /*
         * C API:
         * // Sets the `initial_max_stream_data_bidi_remote` transport parameter.
         * void quiche_config_set_initial_max_stream_data_bidi_remote(quiche_config *config, uint64_t v);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Config.SetInitialMaxStreamDataBidiRemote)]

        internal static partial void QuicheConfigSetInitialMaxStreamDataBidiRemote(SafeHandle configHandle, ulong v);

        /*
         * C API:
         * // Sets the `initial_max_stream_data_uni` transport parameter.
         * void quiche_config_set_initial_max_stream_data_uni(quiche_config *config, uint64_t v);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Config.SetInitialMaxStreamDataUni)]

        internal static partial void QuicheConfigSetInitialMaxStreamDataUni(SafeHandle configHandle, ulong v);

        /*
         * C API:
         * // Sets the `initial_max_streams_bidi` transport parameter.
         * void quiche_config_set_initial_max_streams_bidi(quiche_config *config, uint64_t v);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Config.SetInitialMaxStreamsBidi)]

        internal static partial void QuicheConfigSetInitialMaxStreamsBidi(SafeHandle configHandle, ulong v);

        /*
         * C API:
         * // Sets the `initial_max_streams_uni` transport parameter.
         * void quiche_config_set_initial_max_streams_uni(quiche_config *config, uint64_t v);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Config.SetInitialMaxStreamsUni)]

        internal static partial void QuicheConfigSetInitialMaxStreamsUni(SafeHandle configHandle, ulong v);

        /*
         * C API:
         * // Sets the `ack_delay_exponent` transport parameter.
         * void quiche_config_set_ack_delay_exponent(quiche_config *config, uint64_t v);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Config.SetAckDelayExponent)]

        internal static partial void QuicheConfigSetAckDelayExponent(SafeHandle configHandle, ulong v);

        /*
         * C API:
         * // Sets the `max_ack_delay` transport parameter.
         * void quiche_config_set_max_ack_delay(quiche_config *config, uint64_t v);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Config.SetMaxAckDelay)]

        internal static partial void QuicheConfigSetMaxAckDelay(SafeHandle configHandle, ulong v);

        /*
         * C API:
         * // Sets the `disable_active_migration` transport parameter.
         * void quiche_config_set_disable_active_migration(quiche_config *config, bool v);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Config.SetDisableActiveMigration)]

        internal static partial void QuicheConfigSetDisableActiveMigration(SafeHandle configHandle, [MarshalAs(UnmanagedType.U1)] bool v);

        /*
         * C API:
         * // Sets the congestion control algorithm used by string.
         * int quiche_config_set_cc_algorithm_name(quiche_config *config, const char *algo);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Config.SetCcAlgorithmByName)]

        internal static partial int QuicheConfigSetCcAlgorithmByName(SafeHandle configHandle, [MarshalAs(UnmanagedType.LPStr)] string ccAlgorithmName);

        /*
         * C API:
         * // Sets the initial cwnd for the connection in terms of packet count.
         * void quiche_config_set_initial_congestion_window_packets(quiche_config *config, size_t packets);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Config.SetInitialCongestionWindowPackets)]

        internal static partial void QuicheConfigSetInitialCongestionWindowPackets(SafeHandle configHandle, SizeT packets);

        /*
         * C API:
         * // Sets the congestion control algorithm used.
         * void quiche_config_set_cc_algorithm(quiche_config *config, enum quiche_cc_algorithm algo);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Config.SetCcAlgorithm)]

        internal static partial void QuicheConfigSetCcAlgorithm(SafeHandle configHandle, QuicheCcAlgorithm ccAlgorithm);

        /*
         * C API:
         * // Configures whether to use HyStart++.
         * void quiche_config_enable_hystart(quiche_config *config, bool v);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Config.EnableHystart)]

        internal static partial void QuicheConfigEnableHystart(SafeHandle configHandle, [MarshalAs(UnmanagedType.U1)] bool v);

        /*
         * C API:
         * // Configures whether to enable pacing (enabled by default).
         * void quiche_config_enable_pacing(quiche_config *config, bool v);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Config.EnablePacing)]

        internal static partial void QuicheConfigEnablePacing(SafeHandle configHandle, [MarshalAs(UnmanagedType.U1)] bool v);

        /*
         * C API:
         * // Configures max pacing rate to be used.
         * void quiche_config_set_max_pacing_rate(quiche_config *config, uint64_t v);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Config.SetMaxPacingRate)]

        internal static partial void QuicheConfigSetMaxPacingRate(SafeHandle configHandle, ulong v);

        /*
         * C API:
         * // Configures whether to enable receiving DATAGRAM frames.
         * void quiche_config_enable_dgram(quiche_config *config, bool enabled,
         *                      size_t recv_queue_len,
         *                      size_t send_queue_len);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Config.EnableDgram)]

        internal static partial void QuicheConfigEnableDgram(SafeHandle configHandle, [MarshalAs(UnmanagedType.U1)] bool enabled, SizeT recvQueueLen, SizeT sendQueueLen);

        /*
         * C API:
         * // Sets the maximum connection window.
         * void quiche_config_set_max_connection_window(quiche_config *config, uint64_t v);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Config.SetMaxConnectionWindow)]

        internal static partial void QuicheConfigSetMaxConnectionWindow(SafeHandle configHandle, ulong v);

        /*
         * C API:
         * // Sets the maximum stream window.
         * void quiche_config_set_max_stream_window(quiche_config *config, uint64_t v);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Config.SetMaxStreamWindow)]

        internal static partial void QuicheConfigSetMaxStreamWindow(SafeHandle configHandle, ulong v);

        /*
         * C API:
         * // Sets the limit of active connection IDs.
         * void quiche_config_set_active_connection_id_limit(quiche_config *config, uint64_t v);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Config.SetActiveConnectionIdLimit)]

        internal static partial void QuicheConfigSetActiveConnectionIdLimit(SafeHandle configHandle, ulong v);

        /*
         * C API:
         * // Sets the initial stateless reset token. |v| must contain 16 bytes, otherwise the behaviour is undefined.
         * void quiche_config_set_stateless_reset_token(quiche_config *config, const uint8_t *v);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Config.SetStatelessResetToken)]

        internal static partial void QuicheConfigSetStatelessResetToken(SafeHandle configHandle, ReadOnlySpan<byte> token);

        /*
         * C API:
         * // Frees the config object.
         * void quiche_config_free(quiche_config *config);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Config.Free)]

        internal static partial void QuicheConfigFree(SafeHandle configHandle);

        #endregion

        /*
         * C API:
         * // Extracts version, type, source / destination connection ID and address
         * // verification token from the packet in |buf|.
         * int quiche_header_info(const uint8_t *buf, size_t buf_len, size_t dcil,
         *             uint32_t *version, uint8_t *type,
         *             uint8_t *scid, size_t *scid_len,
         *             uint8_t *dcid, size_t *dcid_len,
         *             uint8_t *token, size_t *token_len);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.HeaderInfo)]
        internal static partial int QuicheHeaderInfo(ReadOnlySpan<byte> buf, ulong bufLen, SizeT dcil, out uint version, out byte type, Span<byte> scid, out nuint scid_len, Span<byte> dcid, out nuint dcidLen, Span<byte> token, out nuint tokenLen);

        /*
         * C API:
         * // Creates a new server-side connection.
         * quiche_conn *quiche_accept(const uint8_t *scid, size_t scid_len,
         *                 const uint8_t *odcid, size_t odcid_len,
         *                 const struct sockaddr *local, size_t local_len,
         *                 const struct sockaddr *peer, size_t peer_len,
         *                 quiche_config *config);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Accept)]
        internal static partial QuicheConnPtr QuicheAccept(ReadOnlySpan<byte> scid, SizeT scidLen, ReadOnlySpan<byte> odcid, SizeT odcidLen, ref SystemStructures.SockAddr localAddr, SizeT localAddrLen, ref SystemStructures.SockAddr peerAddr, SizeT peerAddrLen, SafeHandle configHandle);

        /*
         * C API:
         * // Creates a new client-side connection.
         * quiche_conn *quiche_connect(const char *server_name,
         *                  const uint8_t *scid, size_t scid_len,
         *                  const struct sockaddr *local, size_t local_len,
         *                  const struct sockaddr *peer, size_t peer_len,
         *                  quiche_config *config);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Connect)]
        internal static partial QuicheConnPtr QuicheConnect([MarshalAs(UnmanagedType.LPStr)] string serverName, ReadOnlySpan<byte> scid, SizeT scidLen, ref SystemStructures.SockAddr localAddr, SizeT localAddrLen, ref SystemStructures.SockAddr peerAddr, SizeT peerAddrLen, SafeHandle configHandle);

        /*
         * C API:
         * // Writes a version negotiation packet.
         * ssize_t quiche_negotiate_version(const uint8_t *scid, size_t scid_len,
         *                       const uint8_t *dcid, size_t dcid_len,
         *                       uint8_t *out, size_t out_len);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.NegotiateVersion)]
        internal static partial SignedSizeT QuicheNegotiateVersion(ReadOnlySpan<byte> scid, SizeT scidLen, ReadOnlySpan<byte> dcid, SizeT dcidLen, Span<byte> buffer, SizeT bufferLen);

        /*
         * C API:
         * // Writes a retry packet.
         * ssize_t quiche_retry(const uint8_t *scid, size_t scid_len,
         *           const uint8_t *dcid, size_t dcid_len,
         *           const uint8_t *new_scid, size_t new_scid_len,
         *           const uint8_t *token, size_t token_len,
         *           uint32_t version, uint8_t *out, size_t out_len);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Retry)]
        internal static partial SignedSizeT QuicheRetry(ReadOnlySpan<byte> scid, SizeT scidLen, ReadOnlySpan<byte> dcid, SizeT dcidLen, ReadOnlySpan<byte> newScid, SizeT newScidLen, ReadOnlySpan<byte> token, SizeT tokenLen, uint version, ReadOnlySpan<byte> buffer, SizeT bufferLen);

        /*
         * C API:
         * // Returns true if the given protocol version is supported.
         * bool quiche_version_is_supported(uint32_t version);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.VersionIsSupported)]
        [return: MarshalAs(UnmanagedType.U1)]
        internal static partial bool QuicheVersionIsSupported(uint version);

        /*
         * C API:
         * // Creates a new quiche connection with tls information.
         * quiche_conn *quiche_conn_new_with_tls(const uint8_t *scid, size_t scid_len,
         *                            const uint8_t *odcid, size_t odcid_len,
         *                            const struct sockaddr *local, size_t local_len,
         *                            const struct sockaddr *peer, size_t peer_len,
         *                            const quiche_config *config, void *ssl,
         *                            bool is_server);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Conn.NewWithTls)]
        internal static partial QuicheConnPtr QuicheConnNewWithTls(
            ReadOnlySpan<byte> scid, SizeT scidLen,
            ReadOnlySpan<byte> odcid, SizeT odcidLen,
            ref SystemStructures.SockAddr localAddr, SizeT localAddrLen,
            ref SystemStructures.SockAddr peerAddr, SizeT peerAddrLen,
            SafeHandle configHandle, void* ssl,
            [MarshalAs(UnmanagedType.U1)] bool isServer
        );

        /*
         * C API:
         * // Enables keylog to the specified file path. Returns true on success.
         * bool quiche_conn_set_keylog_path(quiche_conn *conn, const char *path);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Conn.SetKeylogPath)]

        [return: MarshalAs(UnmanagedType.U1)]
        internal static partial bool QuicheConnSetKeylogPath(SafeHandle conn, [MarshalAs(UnmanagedType.LPStr)] string path);

        /*
         * C API:
         * // Enables qlog to the specified file path. Returns true on success.
         * bool quiche_conn_set_qlog_path(quiche_conn *conn, const char *path,
         *                const char *log_title, const char *log_desc);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Conn.SetQlogPath)]

        [return: MarshalAs(UnmanagedType.U1)]
        internal static partial bool QuicheConnSetQlogPath(SafeHandle conn, [MarshalAs(UnmanagedType.LPStr)] string path, [MarshalAs(UnmanagedType.LPStr)] string logTitle, [MarshalAs(UnmanagedType.LPStr)] string logDescription);

        /*
         * C API:
         * // Configures the given session for resumption.
         * int quiche_conn_set_session(quiche_conn *conn, const uint8_t *buf, size_t buf_len);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Conn.SetSession)]

        internal static partial int QuicheConnSetSession(SafeHandle conn, ReadOnlySpan<byte> session, SizeT sessionLen);

        /*
         * C API:
         * // Processes QUIC packets received from the peer.
         * ssize_t quiche_conn_recv(quiche_conn *conn, uint8_t *buf, size_t buf_len,
         *               const quiche_recv_info *info);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Conn.Recv)]

        internal static partial SignedSizeT QuicheConnRecv(SafeHandle conn, Span<byte> buf, ulong bufLen, ref QuicheRecvInfo recvInfo);

        /*
         * C API:
         * // Writes a single QUIC packet to be sent to the peer.
         * ssize_t quiche_conn_send(quiche_conn *conn, uint8_t *out, size_t out_len,
         *               quiche_send_info *out_info);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Conn.Send)]

        internal static partial SignedSizeT QuicheConnSend(SafeHandle conn, Span<byte> buf, ulong bufLen, out QuicheSendInfo sendInfo);

        /*
         * C API:
         * // Returns the size of the send quantum, in bytes.
         * size_t quiche_conn_send_quantum(const quiche_conn *conn);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Conn.SendQuantum)]

        internal static partial SizeT QuicheConnSendQuantum(SafeHandle conn);

        /*
         * C API:
         * // Reads contiguous data from a stream.
         * ssize_t quiche_conn_stream_recv(quiche_conn *conn, uint64_t stream_id,
         *                      uint8_t *out, size_t buf_len, bool *fin);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Conn.Stream.Recv)]

        internal static partial SignedSizeT QuicheConnStreamRecv(SafeHandle conn, ulong streamId, Span<byte> buf, ulong bufLen, [MarshalAs(UnmanagedType.U1)] out bool fin);

        /*
         * C API:
         * // Writes data to a stream.
         * ssize_t quiche_conn_stream_send(quiche_conn *conn, uint64_t stream_id,
         *                      const uint8_t *buf, size_t buf_len, bool fin);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Conn.Stream.Send)]

        internal static partial SignedSizeT QuicheConnStreamSend(SafeHandle conn, ulong streamId, ReadOnlySpan<byte> buf, ulong bufLen, [MarshalAs(UnmanagedType.U1)] bool fin);

        /*
         * C API:
         * // Sets the priority for a stream.
         * int quiche_conn_stream_priority(quiche_conn *conn, uint64_t stream_id,
         *                      uint8_t urgency, bool incremental);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Conn.Stream.Priority)]

        internal static partial int QuicheConnStreamPriority(SafeHandle conn, ulong streamId, byte urgency, [MarshalAs(UnmanagedType.U1)] bool incremental);

        /*
         * C API:
         * // Shuts down reading or writing from/to the specified stream.
         * int quiche_conn_stream_shutdown(quiche_conn *conn, uint64_t stream_id,
         *                      enum quiche_shutdown direction, uint64_t err);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Conn.Stream.Shutdown)]

        internal static partial int QuicheConnStreamShutdown(SafeHandle conn, ulong streamId, QuicheShutdown direction, ulong err);

        /*
         * C API:
         * // Returns the stream's send capacity in bytes.
         * ssize_t quiche_conn_stream_capacity(const quiche_conn *conn, uint64_t stream_id);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Conn.Stream.Capacity)]

        internal static partial SignedSizeT QuicheConnStreamCapacity(SafeHandle conn, ulong streamId);

        /*
         * C API:
         * // Returns true if the stream has data that can be read.
         * bool quiche_conn_stream_readable(const quiche_conn *conn, uint64_t stream_id);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Conn.Stream.Readable)]

        [return: MarshalAs(UnmanagedType.U1)]
        internal static partial bool QuicheConnStreamReadable(SafeHandle conn, ulong streamId);

        /*
         * C API:
         * // Returns the next stream that has data to read, or -1 if no such stream is
         * // available.
         * int64_t quiche_conn_stream_readable_next(quiche_conn *conn);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Conn.Stream.ReadableNext)]

        internal static partial long QuicheConnStreamReadableNext(SafeHandle conn);

        /*
         * C API:
         * // Returns true if the stream has enough send capacity.
         * //
         * // On error a value lower than 0 is returned.
         * int quiche_conn_stream_writable(quiche_conn *conn, uint64_t stream_id, size_t len);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Conn.Stream.Writable)]

        internal static partial int QuicheConnStreamWritable(SafeHandle conn, ulong streamId, SizeT len);

        /*
         * C API:
         * // Returns the next stream that can be written to, or -1 if no such stream is
         * // available.
         * int64_t quiche_conn_stream_writable_next(quiche_conn *conn);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Conn.Stream.WritableNext)]

        internal static partial long QuicheConnStreamWritableNext(SafeHandle conn);

        /*
         * C API:
         * // Returns true if all the data has been read from the specified stream.
         * bool quiche_conn_stream_finished(const quiche_conn *conn, uint64_t stream_id);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Conn.Stream.Finished)]

        [return: MarshalAs(UnmanagedType.U1)]
        internal static partial bool QuicheConnStreamFinished(SafeHandle conn, ulong streamId);

        /*
         * C API:
         * // Returns an iterator over streams that have outstanding data to read.
         * quiche_stream_iter *quiche_conn_readable(const quiche_conn *conn);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Conn.Readable)]

        internal static partial QuicheStreamIterPtr QuicheConnReadable(SafeHandle conn);

        /*
         * C API:
         * // Returns an iterator over streams that can be written to.
         * quiche_stream_iter *quiche_conn_writable(const quiche_conn *conn);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Conn.Writable)]

        internal static partial QuicheStreamIterPtr QuicheConnWritable(SafeHandle conn);

        /*
         * C API:
         * // Returns the maximum possible size of egress UDP payloads.
         * size_t quiche_conn_max_send_udp_payload_size(const quiche_conn *conn);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Conn.MaxSendUdpPayloadSize)]

        internal static partial SizeT QuicheConnMaxSendUdpPayloadSize(SafeHandle conn);

        /*
         * C API:
         * // Returns the amount of time until the next timeout event, in nanoseconds.
         * uint64_t quiche_conn_timeout_as_nanos(const quiche_conn *conn);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Conn.TimeoutAsNanos)]

        internal static partial ulong QuicheConnTimeoutAsNanos(SafeHandle conn);

        /*
         * C API:
         * // Returns the amount of time until the next timeout event, in milliseconds.
         * uint64_t quiche_conn_timeout_as_millis(const quiche_conn *conn);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Conn.TimeoutAsMillis)]

        internal static partial ulong QuicheConnTimeoutAsMillis(SafeHandle conn);

        /*
         * C API:
         * // Processes a timeout event.
         * void quiche_conn_on_timeout(quiche_conn *conn);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Conn.OnTimeout)]

        internal static partial void QuicheConnOnTimeout(SafeHandle conn);

        /*
         * C API:
         *  // Closes the connection with the given error and reason.
         *  int quiche_conn_close(quiche_conn *conn, bool app, uint64_t err,
         *             const uint8_t *reason, size_t reason_len);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Conn.Close)]

        internal static partial int QuicheConnClose(SafeHandle conn, [MarshalAs(UnmanagedType.U1)] bool app, ulong error, ReadOnlySpan<byte> reason, ulong reasonLen);

        /*
         * C API:
         * // Returns a string uniquely representing the connection.
         * void quiche_conn_trace_id(const quiche_conn *conn, const uint8_t **out, size_t *out_len);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Conn.TraceId)]

        internal static partial void QuicheConnTraceId(SafeHandle conn, byte** dst, out ulong dstLen);

        /*
         * C API:
         * // Returns the source connection ID.
         * void quiche_conn_source_id(const quiche_conn *conn, const uint8_t **out, size_t *out_len);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Conn.SourceId)]

        internal static partial void QuicheConnSourceId(SafeHandle conn, byte** dst, out ulong dstLen);

        /*
         * C API:
         * // Returns the destination connection ID.
         * void quiche_conn_destination_id(const quiche_conn *conn, const uint8_t **out, size_t *out_len);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Conn.DestinationId)]

        internal static partial void QuicheConnDestinationId(SafeHandle conn, byte** dst, out ulong dstLen);

        /*
         * C API:
         * // Returns the negotiated ALPN protocol.
         * void quiche_conn_application_proto(const quiche_conn *conn, const uint8_t **out,
         *                    size_t *out_len);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Conn.ApplicationProto)]

        internal static partial void QuicheConnApplicationProto(SafeHandle conn, byte** dst, out ulong dstLen);

        /*
         * C API:
         * // Returns the peer's leaf certificate (if any) as a DER-encoded buffer.
         * void quiche_conn_peer_cert(const quiche_conn *conn, const uint8_t **out, size_t *out_len);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Conn.PeerCert)]

        internal static partial void QuicheConnPeerCert(SafeHandle conn, byte** dst, out ulong dstLen);

        /*
         *  C API:
         * // Returns the serialized cryptographic session for the connection.
         * void quiche_conn_session(const quiche_conn *conn, const uint8_t **out, size_t *out_len);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Conn.Session)]

        internal static partial void QuicheConnSession(SafeHandle conn, byte** dst, out ulong dstLen);

        /*
         * C API:
         * // Returns true if the connection handshake is complete.
         * bool quiche_conn_is_established(const quiche_conn *conn);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Conn.IsEstablished)]

        [return: MarshalAs(UnmanagedType.U1)]
        internal static partial bool QuicheConnIsEstablished(SafeHandle conn);

        /*
         * C API:
         * // Returns true if the connection has a pending handshake that has progressed
         * // enough to send or receive early data.
         * bool quiche_conn_is_in_early_data(const quiche_conn *conn);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Conn.IsInEarlyData)]

        [return: MarshalAs(UnmanagedType.U1)]
        internal static partial bool QuicheConnIsInEarlyData(SafeHandle conn);

        /*
         * C API:
         * // // Returns whether there is stream or DATAGRAM data available to read.
         * bool quiche_conn_is_readable(const quiche_conn *conn);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Conn.IsReadable)]

        [return: MarshalAs(UnmanagedType.U1)]
        internal static partial bool QuicheConnIsReadable(SafeHandle conn);

        /*
         * C API:
         * // Returns true if the connection is in the process of being closed.
         * bool quiche_conn_is_draining(const quiche_conn *conn);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Conn.IsDraining)]

        [return: MarshalAs(UnmanagedType.U1)]
        internal static partial bool QuicheConnIsDraining(SafeHandle conn);

        /*
         * C API:
         * // Returns the number of bidirectional streams that can be created
         * // before the peer's stream count limit is reached.
         * uint64_t quiche_conn_peer_streams_left_bidi(const quiche_conn *conn);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Conn.PeerStreamsLeftBidi)]

        internal static partial ulong QuicheConnPeerStreamsLeftBidi(SafeHandle conn);

        /*
         * C API:
         * // Returns the number of unidirectional streams that can be created
         * // before the peer's stream count limit is reached.
         * uint64_t quiche_conn_peer_streams_left_uni(const quiche_conn *conn);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Conn.PeerStreamsLeftUni)]

        internal static partial ulong QuicheConnPeerStreamsLeftUni(SafeHandle conn);

        /*
         * C API:
         * // Returns true if the connection is closed.
         * bool quiche_conn_is_closed(const quiche_conn *conn);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Conn.IsClosed)]

        [return: MarshalAs(UnmanagedType.U1)]
        internal static partial bool QuicheConnIsClosed(SafeHandle conn);

        /*
         * C API:
         * // Returns true if the connection was closed due to the idle timeout.
         * bool quiche_conn_is_timed_out(const quiche_conn *conn);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Conn.IsTimedOut)]

        [return: MarshalAs(UnmanagedType.U1)]
        internal static partial bool QuicheConnIsTimedOut(SafeHandle conn);

        /*
         * C API:
         * // Returns true if a connection error was received, and updates the provided
         * // parameters accordingly.
         * bool quiche_conn_peer_error(const quiche_conn *conn,
         *                  bool *is_app,
         *                  uint64_t *error_code,
         *                  const uint8_t **reason,
         *                  size_t *reason_len);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Conn.PeerError)]

        [return: MarshalAs(UnmanagedType.U1)]
        internal static partial bool QuicheConnPeerError(SafeHandle conn, [MarshalAs(UnmanagedType.U1)] out bool isApp, out ulong errorCode, byte** reason, out SizeT reasonLen);

        /*
         * C API:
         * // Returns true if a connection error was queued or sent, and updates the provided
         * // parameters accordingly.
         * bool quiche_conn_local_error(const quiche_conn *conn,
         *                  bool *is_app,
         *                  uint64_t *error_code,
         *                  const uint8_t **reason,
         *                  size_t *reason_len);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Conn.LocalError)]

        [return: MarshalAs(UnmanagedType.U1)]
        internal static partial bool QuicheConnLocalError(SafeHandle conn, [MarshalAs(UnmanagedType.U1)] out bool isApp, out ulong errorCode, byte** reason, out SizeT reasonLen);

        /*
         * C API:
         * // Fetches the next stream from the given iterator. Returns false if there are
         * // no more elements in the iterator.
         * bool quiche_stream_iter_next(quiche_stream_iter *iter, uint64_t *stream_id);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Stream.IterNext)]

        [return: MarshalAs(UnmanagedType.U1)]
        internal static partial bool QuicheStreamIterNext(SafeHandle iterHandle, out ulong streamId);

        /*
         * C API:
         * // Frees the given stream iterator.
         * void quiche_stream_iter_free(quiche_stream_iter *iter);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Stream.IterFree)]

        internal static partial void QuicheStreamIterFree(SafeHandle iterHandle);

        /*
         * C API:
         * // Collects and returns statistics about the connection.
         * void quiche_conn_stats(const quiche_conn *conn, quiche_stats *out);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Stats.Conn)]

        internal static partial void QuicheConnStats(SafeHandle conn, out QuicheStats stats);

        /*
         * C API:
         * // Returns the peer's transport parameters in |out|. Returns false if we have
         * // not yet processed the peer's transport parameters.
         * bool quiche_conn_peer_transport_params(const quiche_conn *conn, quiche_transport_params *out);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Stats.ConnPeerTransportParams)]

        [return: MarshalAs(UnmanagedType.U1)]
        internal static partial bool QuicheConnPeerTransportParams(SafeHandle conn, out QuicheTransportParameters transportParams);

        /*
         * C API:
         * // Collects and returns statistics about the specified path for the connection.
         * //
         * // The `idx` argument represent the path's index (also see the `paths_count`
         * // field of `quiche_stats`).
         * int quiche_conn_path_stats(const quiche_conn *conn, size_t idx, quiche_path_stats *out);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Stats.ConnPath)]

        internal static partial int QuicheConnPathStats(SafeHandle conn, SizeT index, out QuichePathStats stats);

        /*
         * C API:
         * // Returns whether or not this is a server-side connection.
         * bool quiche_conn_is_server(const quiche_conn *conn);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Conn.IsServer)]

        [return: MarshalAs(UnmanagedType.U1)]
        internal static partial bool QuicheConnIsServer(SafeHandle conn);

        /*
         * C API:
         * // Returns the maximum DATAGRAM payload that can be sent.
         * ssize_t quiche_conn_dgram_max_writable_len(const quiche_conn *conn);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Conn.Dgram.MaxWritableLen)]

        internal static partial SignedSizeT QuicheConnDgramMaxWritableLen(SafeHandle conn);

        /*
         * C API:
         * // Returns the length of the first stored DATAGRAM.
         * ssize_t quiche_conn_dgram_recv_front_len(const quiche_conn *conn);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Conn.Dgram.RecvFrontLen)]

        internal static partial SignedSizeT QuicheConnDgramRecvFrontLen(SafeHandle conn);

        /*
         * C API:
         * // Returns the number of items in the DATAGRAM receive queue.
         * ssize_t quiche_conn_dgram_recv_queue_len(const quiche_conn *conn);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Conn.Dgram.RecvQueueLen)]

        internal static partial SignedSizeT QuicheConnDgramRecvQueueLen(SafeHandle conn);

        /*
         * C API:
         * // Returns the total size of all items in the DATAGRAM receive queue.
         * ssize_t quiche_conn_dgram_recv_queue_byte_size(const quiche_conn *conn);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Conn.Dgram.RecvQueueByteSize)]

        internal static partial SignedSizeT QuicheConnDgramRecvQueueByteSize(SafeHandle conn);

        /*
         * C API:
         * // Returns the number of items in the DATAGRAM send queue.
         * ssize_t quiche_conn_dgram_send_queue_len(const quiche_conn *conn);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Conn.Dgram.SendQueueLen)]

        internal static partial SignedSizeT QuicheConnDgramSendQueueLen(SafeHandle conn);

        /*
         * C API:
         * // Returns the total size of all items in the DATAGRAM send queue.
         * ssize_t quiche_conn_dgram_send_queue_byte_size(const quiche_conn *conn);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Conn.Dgram.SendQueueByteSize)]

        internal static partial SignedSizeT QuicheConnDgramSendQueueByteSize(SafeHandle conn);

        /*
         * C API:
         * // Reads the first received DATAGRAM.
         * ssize_t quiche_conn_dgram_recv(quiche_conn *conn, uint8_t *buf,
         *                     size_t buf_len);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Conn.Dgram.Recv)]

        internal static partial SignedSizeT QuicheConnDgramRecv(SafeHandle conn, Span<byte> buffer, SizeT bufferLength);

        /*
         * C API:
         * // Sends data in a DATAGRAM frame.
         * ssize_t quiche_conn_dgram_send(quiche_conn *conn, const uint8_t *buf,
         *                     size_t buf_len);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Conn.Dgram.Send)]

        internal static partial SignedSizeT QuicheConnDgramSend(SafeHandle conn, ReadOnlySpan<byte> buffer, SizeT bufferLength);

        /*
         * C API:
         * // Purges queued outgoing DATAGRAMs matching the predicate.
         * void quiche_conn_dgram_purge_outgoing(quiche_conn *conn,
         *                            bool (*f)(uint8_t *, size_t));
         */
        //[LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Conn.Dgram.PurgeOutgoing)]

        //internal static partial void QuicheConnDgramPurgeOutgoing(SafeHandle conn, [MarshalAs(UnmanagedType.FunctionPtr)] QuicheConnDgramPurgeOutgoingCallback callback);
        //internal delegate void QuicheConnDgramPurgeOutgoingCallback(Span<byte> buffer, SizeT bufferLength);

        /*
         * C API:
         * // Schedule an ack-eliciting packet on the active path.
         * ssize_t quiche_conn_send_ack_eliciting(quiche_conn *conn);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Conn.SendAckEliciting)]

        internal static partial SignedSizeT QuicheConnSendAckEliciting(SafeHandle conn);

        /*
         * C API:
         * // Schedule an ack-eliciting packet on the specified path.
         * ssize_t quiche_conn_send_ack_eliciting_on_path(quiche_conn *conn,
         *                 const struct sockaddr *local, size_t local_len,
         *                 const struct sockaddr *peer, size_t peer_len);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Conn.SendAckElicitingOnPath)]

        internal static partial SignedSizeT QuicheConnSendAckElicitingOnPath(SafeHandle conn, ref SystemStructures.SockAddr localAddress, SizeT localAddressLength, ref SystemStructures.SockAddr peerAddress, SizeT peerAddressLength);

        /*
         * C API:
         * // Frees the connection object.
         * void quiche_conn_free(quiche_conn *conn);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.Conn.Free)]

        internal static partial void QuicheConnFree(SafeHandle conn);

        /*
         * C API:
         * // Writes an unsigned variable-length integer in network byte-order into
         * // the provided buffer.
         * int quiche_put_varint(uint8_t *buf, size_t buf_len,
         *            uint64_t val);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.PutVarInt)]

        internal static partial int QuichePutVarInt(Span<byte> buffer, SizeT bufferLength, ulong value);

        /*
         * C API:
         * // Reads an unsigned variable-length integer in network byte-order from
         * // the provided buffer and returns the wire length.
         * ssize_t quiche_get_varint(const uint8_t *buf, size_t buf_len,
         *                uint64_t val);
         */
        [LibraryImport(QuicheLibraryName, EntryPoint = QuicheApiNames.GetVarInt)]

        internal static partial SignedSizeT QuicheGetVarInt(ReadOnlySpan<byte> buffer, SizeT bufferLength, ulong value);
    }
}
