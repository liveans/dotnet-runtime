// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Runtime.InteropServices;

namespace System.Net.Quic.Implementations.Quiche
{
    public class SystemStructures
    {
        [StructLayout(LayoutKind.Sequential)]
        public unsafe struct SockAddr
        {
#pragma warning disable CS3003 // Type is not CLS-compliant
            public ushort sa_family;
            public fixed byte sa_data[14];
        }

        [StructLayout(LayoutKind.Sequential, Pack = 128)]
        public struct SockAddrStorage // Should be aligned to 128 bytes
        {
            public ushort ss_family;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct Timespec
        {
            public long tv_sec;
            public CLong tv_nsec;
#pragma warning restore CS3003 // Type is not CLS-compliant
        }
    }
}
