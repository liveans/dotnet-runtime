// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace System.Net.Quic.System.Net.Quic.Interop.quiche
{
    [StructLayout(LayoutKind.Explicit)]
    internal struct QuicAddrFamilyAndLen
    {
        [FieldOffset(0)]
        public ushort sin_family;
        [FieldOffset(0)]
        public byte sin_len;
        [FieldOffset(1)]
        public byte sin_family_bsd;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal unsafe struct QuicAddrIn
    {
        public QuicAddrFamilyAndLen sin_family;
        public ushort sin_port;
        public fixed byte sin_addr[4];
    }

    [StructLayout(LayoutKind.Sequential)]
    internal unsafe struct QuicAddrIn6
    {
        public QuicAddrFamilyAndLen sin6_family;
        public ushort sin6_port;
        public uint sin6_flowinfo;
        public fixed byte sin6_addr[16];
        public uint sin6_scope_id;
    }

    [StructLayout(LayoutKind.Explicit)]
    internal struct QuicAddr
    {
        [FieldOffset(0)]
        public QuicAddrIn Ipv4;
        [FieldOffset(0)]
        public QuicAddrIn6 Ipv6;
        [FieldOffset(0)]
        public QuicAddrFamilyAndLen FamilyLen;

        public static bool SockaddrHasLength => OperatingSystem.IsFreeBSD() || OperatingSystem.IsIOS() || OperatingSystem.IsMacOS() || OperatingSystem.IsMacCatalyst() || OperatingSystem.IsTvOS() || OperatingSystem.IsWatchOS();

        public int Family
        {
            get
            {
                if (SockaddrHasLength)
                {
                    return FamilyLen.sin_family_bsd;
                }
                else
                {
                    return FamilyLen.sin_family;
                }
            }
            set
            {
                if (SockaddrHasLength)
                {
                    FamilyLen.sin_family_bsd = (byte)value;
                }
                else
                {
                    FamilyLen.sin_family = (ushort)value;
                }
            }
        }
    }
}
