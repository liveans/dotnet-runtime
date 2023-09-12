// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Collections.Generic;
using System.Net.Security;

namespace System.Net.Quic.Implementations.Quiche
{
    internal sealed class QuicheConfig
    {
        private QuicheConfigSafeHandle _handle;
        internal QuicheConfigSafeHandle Handle { get { return _handle; } }
        internal QuicheConfig()
        {
            //_handle = new QuicheConfigSafeHandle(0xbabababa);
            _handle = new QuicheConfigSafeHandle(0x00000001);
            bool success = true;
            _handle.DangerousAddRef(ref success);
        }

        internal int LoadCertChainFromPemFile(string path)
        {
            return QuicheApi.QuicheConfigLoadCertChainFromPemFile(_handle, path);
        }

        internal int LoadPrivKeyFromPemFile(string path)
        {
            return QuicheApi.QuicheConfigLoadPrivKeyFromPemFile(_handle, path);
        }

        internal int LoadVerifyLocationsFromFile(string path)
        {
            return QuicheApi.QuicheConfigLoadVerifyLocationsFromFile(_handle, path);
        }

        internal int LoadVerifyLocationsFromDirectory(string path)
        {
            return QuicheApi.QuicheConfigLoadVerifyLocationsFromDirectory(_handle, path);
        }

        internal void EnableVerifyPeer(bool v = true)
        {
            QuicheApi.QuicheConfigVerifyPeer(_handle, v);
        }

        internal void EnableGrease(bool v = true)
        {
            QuicheApi.QuicheConfigGrease(_handle, v);
        }

        internal void EnableLogKeys()
        {
            QuicheApi.QuicheConfigLogKeys(_handle);
        }

        internal void EnableEarlyData()
        {
            QuicheApi.QuicheConfigEnableEarlyData(_handle);
        }

        public int SetApplicationProtocols(ReadOnlySpan<SslApplicationProtocol> protocols)
        {
            List<byte> alpns = new();
            foreach (var proto in protocols)
            {
                var protocol = proto.Protocol;
                alpns.Add((byte)protocol.Length);
                alpns.AddRange(protocol.ToArray());
            }

            return QuicheApi.QuicheConfigSetApplicationProtocols(_handle, new ReadOnlySpan<byte>(alpns.ToArray()), (nuint)alpns.Count);
        }

        internal void SetMaxIdleTimeout(ulong maxIdleTimeout)
        {
            QuicheApi.QuicheConfigSetMaxIdleTimeout(_handle, maxIdleTimeout);
        }

        internal void SetMaxRecvUdpPayloadSize(ulong value)
        {
            QuicheApi.QuicheConfigSetMaxRecvUdpPayloadSize(_handle, (nuint)value);
        }

        internal void SetMaxSendUdpPayloadSize(ulong value)
        {
            QuicheApi.QuicheConfigSetMaxSendUdpPayloadSize(_handle, (nuint)value);
        }

        internal void SetInitialMaxData(ulong value)
        {
            QuicheApi.QuicheConfigSetInitialMaxData(_handle, value);
        }

        internal void SetInitialMaxStreamDataBidiLocal(ulong value)
        {
            QuicheApi.QuicheConfigSetInitialMaxStreamDataBidiLocal(_handle, value);
        }

        internal void SetInitialMaxStreamDataBidiRemote(ulong value)
        {
            QuicheApi.QuicheConfigSetInitialMaxStreamDataBidiRemote(_handle, value);
        }

        internal void SetInitialMaxStreamDataUni(ulong value)
        {
            QuicheApi.QuicheConfigSetInitialMaxStreamDataUni(_handle, value);
        }

        internal void SetInitialMaxStreamsBidi(ulong value)
        {
            QuicheApi.QuicheConfigSetInitialMaxStreamsBidi(_handle, value);
        }

        internal void SetInitialMaxStreamsUni(ulong value)
        {
            QuicheApi.QuicheConfigSetInitialMaxStreamsUni(_handle, value);
        }

        internal void SetAckDelayExponent(ulong value)
        {
            QuicheApi.QuicheConfigSetAckDelayExponent(_handle, value);
        }

        internal void SetMaxAckDelay(ulong value)
        {
            QuicheApi.QuicheConfigSetMaxAckDelay(_handle, value);
        }

        internal void SetDisableActiveMigration(bool value)
        {
            QuicheApi.QuicheConfigSetDisableActiveMigration(_handle, value);
        }

        internal void SetCcAlgorithm(QuicheCcAlgorithm value)
        {
            QuicheApi.QuicheConfigSetCcAlgorithm(_handle, value);
        }

        internal void EnableHystart(bool value)
        {
            QuicheApi.QuicheConfigEnableHystart(_handle, value);
        }

        internal void EnablePacing(bool value)
        {
            QuicheApi.QuicheConfigEnablePacing(_handle, value);
        }

        internal void SetMaxPacingRate(ulong value)
        {
            QuicheApi.QuicheConfigSetMaxPacingRate(_handle, value);
        }

        internal void EnableDatagram(bool enabled, ulong recvQueueLen, ulong sendQueueLen)
        {
            QuicheApi.QuicheConfigEnableDgram(_handle, enabled, (nuint)recvQueueLen, (nuint)sendQueueLen);
        }

        internal void SetMaxConnectionWindow(ulong value)
        {
            QuicheApi.QuicheConfigSetMaxConnectionWindow(_handle, value);
        }

        internal void SetMaxStreamWindow(ulong value)
        {
            QuicheApi.QuicheConfigSetMaxStreamWindow(_handle, value);
        }

        internal void SetActiveConnectionIdLimit(ulong value)
        {
            QuicheApi.QuicheConfigSetActiveConnectionIdLimit(_handle, value);
        }

        internal void SetStatelessResetToken(ReadOnlySpan<byte> token)
        {
            if (token.Length < 16)
            {
                throw new ArgumentException("Token must be at least 16 bytes.");
            }

            QuicheApi.QuicheConfigSetStatelessResetToken(_handle, token);
        }
    }
}
