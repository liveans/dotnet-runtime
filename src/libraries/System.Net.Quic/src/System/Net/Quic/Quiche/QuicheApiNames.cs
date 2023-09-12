// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace System.Net.Quic.Implementations.Quiche
{
    internal static class QuicheApiNames
    {
        internal const string Version = "quiche_version";
        internal const string EnableDebugLogging = "quiche_enable_debug_logging";
        internal const string PutVarInt = "quiche_put_varint";
        internal const string GetVarInt = "quiche_get_varint";

        internal static class Config
        {
            internal const string ConfigurationNew = "quiche_config_new";
            internal const string LoadCertChainFromPemFile = "quiche_config_load_cert_chain_from_pem_file";
            internal const string LoadPrivKeyFromPemFile = "quiche_config_load_priv_key_from_pem_file";
            internal const string LoadVerifyLocationsFromFile = "quiche_config_load_verify_locations_from_file";
            internal const string LoadVerifyLocationsFromDirectory = "quiche_config_load_verify_locations_from_directory";
            internal const string VerifyPeer = "quiche_config_verify_peer";
            internal const string Grease = "quiche_config_grease";
            internal const string LogKeys = "quiche_config_log_keys";
            internal const string EnableEarlyData = "quiche_config_enable_early_data";
            internal const string SetApplicationProtocols = "quiche_config_set_application_protos";
            internal const string SetMaxIdleTimeout = "quiche_config_set_max_idle_timeout";
            internal const string SetMaxRecvUdpPayloadSize = "quiche_config_set_max_recv_udp_payload_size";
            internal const string SetMaxSendUdpPayloadSize = "quiche_config_set_max_send_udp_payload_size";
            internal const string SetInitialMaxData = "quiche_config_set_initial_max_data";
            internal const string SetInitialMaxStreamDataBidiLocal = "quiche_config_set_initial_max_stream_data_bidi_local";
            internal const string SetInitialMaxStreamDataBidiRemote = "quiche_config_set_initial_max_stream_data_bidi_remote";
            internal const string SetInitialMaxStreamDataUni = "quiche_config_set_initial_max_stream_data_uni";
            internal const string SetInitialMaxStreamsBidi = "quiche_config_set_initial_max_streams_bidi";
            internal const string SetInitialMaxStreamsUni = "quiche_config_set_initial_max_streams_uni";
            internal const string SetAckDelayExponent = "quiche_config_set_ack_delay_exponent";
            internal const string SetMaxAckDelay = "quiche_config_set_max_ack_delay";
            internal const string SetDisableActiveMigration = "quiche_config_set_disable_active_migration";
            internal const string SetCcAlgorithmByName = "quiche_config_set_cc_algorithm_name";
            internal const string SetInitialCongestionWindowPackets = "quiche_config_set_initial_congestion_window_packets";
            internal const string SetCcAlgorithm = "quiche_config_set_cc_algorithm";
            internal const string EnableHystart = "quiche_config_enable_hystart";
            internal const string EnablePacing = "quiche_config_enable_pacing";
            internal const string SetMaxPacingRate = "quiche_config_set_max_pacing_rate";
            internal const string EnableDgram = "quiche_config_enable_dgram";
            internal const string SetMaxConnectionWindow = "quiche_config_set_max_connection_window";
            internal const string SetMaxStreamWindow = "quiche_config_set_max_stream_window";
            internal const string SetActiveConnectionIdLimit = "quiche_config_set_active_connection_id_limit";
            internal const string SetStatelessResetToken = "quiche_config_set_stateless_reset_token";
            internal const string Free = "quiche_config_free";

        }
        internal const string HeaderInfo = "quiche_header_info";
        internal const string Accept = "quiche_accept";
        internal const string Connect = "quiche_connect";
        internal const string NegotiateVersion = "quiche_negotiate_version";
        internal const string Retry = "quiche_retry";
        internal const string VersionIsSupported = "quiche_version_is_supported";
        internal static class Conn
        {
            internal const string NewWithTls = "quiche_conn_new_with_tls";
            internal const string SetKeylogPath = "quiche_conn_set_keylog_path";
            internal const string SetKeylogFd = "quiche_conn_set_keylog_fd";
            internal const string SetQlogPath = "quiche_conn_set_qlog_path";
            internal const string SetQlogFd = "quiche_conn_set_qlog_fd";
            internal const string SetSession = "quiche_conn_set_session";
            internal const string Recv = "quiche_conn_recv";
            internal const string Send = "quiche_conn_send";
            internal const string SendQuantum = "quiche_conn_send_quantum";
            internal static class Stream
            {
                internal const string Recv = "quiche_conn_stream_recv";
                internal const string Send = "quiche_conn_stream_send";
                internal const string Priority = "quiche_conn_stream_priority";
                internal const string Shutdown = "quiche_conn_stream_shutdown";
                internal const string Capacity = "quiche_conn_stream_capacity";
                internal const string Readable = "quiche_conn_stream_readable";
                internal const string ReadableNext = "quiche_conn_stream_readable_next";
                internal const string Writable = "quiche_conn_stream_writable";
                internal const string WritableNext = "quiche_conn_stream_writable_next";
                internal const string Finished = "quiche_conn_stream_finished";
            }
            internal const string Readable = "quiche_conn_readable";
            internal const string Writable = "quiche_conn_writable";
            internal const string MaxSendUdpPayloadSize = "quiche_conn_max_send_udp_payload_size";
            internal const string TimeoutAsNanos = "quiche_conn_timeout_as_nanos";
            internal const string TimeoutAsMillis = "quiche_conn_timeout_as_millis";
            internal const string OnTimeout = "quiche_conn_on_timeout";
            internal const string Close = "quiche_conn_close";
            internal const string TraceId = "quiche_conn_trace_id";
            internal const string SourceId = "quiche_conn_source_id";
            internal const string DestinationId = "quiche_conn_destination_id";
            internal const string ApplicationProto = "quiche_conn_application_proto";
            internal const string PeerCert = "quiche_conn_peer_cert";
            internal const string Session = "quiche_conn_session";
            internal const string IsEstablished = "quiche_conn_is_established";
            internal const string IsInEarlyData = "quiche_conn_is_in_early_data";
            internal const string IsReadable = "quiche_conn_is_readable";
            internal const string IsDraining = "quiche_conn_is_draining";
            internal const string PeerStreamsLeftBidi = "quiche_conn_peer_streams_left_bidi";
            internal const string PeerStreamsLeftUni = "quiche_conn_peer_streams_left_uni";
            internal const string IsClosed = "quiche_conn_is_closed";
            internal const string IsTimedOut = "quiche_conn_is_timed_out";
            internal const string PeerError = "quiche_conn_peer_error";
            internal const string LocalError = "quiche_conn_local_error";
            internal static class Dgram
            {
                internal const string MaxWritableLen = "quiche_conn_dgram_max_writable_len";
                internal const string RecvFrontLen = "quiche_conn_dgram_recv_front_len";
                internal const string RecvQueueLen = "quiche_conn_dgram_recv_queue_len";
                internal const string RecvQueueByteSize = "quiche_conn_dgram_recv_queue_byte_size";
                internal const string SendQueueLen = "quiche_conn_dgram_send_queue_len";
                internal const string SendQueueByteSize = "quiche_conn_dgram_send_queue_byte_size";
                internal const string Recv = "quiche_conn_dgram_recv";
                internal const string Send = "quiche_conn_dgram_send";
                internal const string PurgeOutgoing = "quiche_conn_dgram_purge_outgoing";
            }
            internal const string SendAckEliciting = "quiche_conn_send_ack_eliciting";
            internal const string SendAckElicitingOnPath = "quiche_conn_send_ack_eliciting_on_path";
            internal const string Free = "quiche_conn_free";
            internal const string IsServer = "quiche_conn_is_server";
        }
        internal static class Stream
        {
            internal const string IterNext = "quiche_stream_iter_next";
            internal const string IterFree = "quiche_stream_iter_free";

        }
        internal static class Stats
        {
            internal const string Conn = "quiche_conn_stats";
            internal const string ConnPath = "quiche_conn_path_stats";
            internal const string ConnPeerTransportParams = "quiche_conn_peer_transport_params";
        }
    }
}
