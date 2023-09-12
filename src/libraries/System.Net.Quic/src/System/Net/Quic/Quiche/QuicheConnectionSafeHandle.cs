// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Runtime.InteropServices;

namespace System.Net.Quic.Implementations.Quiche
{
    internal sealed class QuicheConnectionSafeHandle : SafeHandle
    {

        public QuicheConnectionSafeHandle(nint handle, bool ownsHandle = true) : base(handle, ownsHandle)
        {
        }

        public override bool IsInvalid => DangerousGetHandle() == IntPtr.Zero;

        protected override bool ReleaseHandle()
        {
            QuicheApi.QuicheConnFree(this);
            SetHandle(IntPtr.Zero);
            SetHandleAsInvalid();

            return true;
        }
    }
}
