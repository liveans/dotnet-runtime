// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Runtime.InteropServices;

namespace System.Net.Quic.Implementations.Quiche
{
    internal sealed unsafe class QuicheConfigSafeHandle : SafeHandle
    {
        internal unsafe QuicheConfigSafeHandle(uint protocolVersion, bool ownsHandle = true) : base(QuicheApi.QuicheConfigNew(protocolVersion), ownsHandle)
        { }

        public override bool IsInvalid => DangerousGetHandle() == IntPtr.Zero;

        protected override bool ReleaseHandle()
        {
            QuicheApi.QuicheConfigFree(this);
            SetHandle(IntPtr.Zero);
            SetHandleAsInvalid();
            return true;
        }
    }
}
