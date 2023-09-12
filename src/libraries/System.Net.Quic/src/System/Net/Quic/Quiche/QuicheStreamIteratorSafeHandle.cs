// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Runtime.InteropServices;

namespace System.Net.Quic.Implementations.Quiche
{
    internal sealed class QuicheStreamIteratorSafeHandle : SafeHandle
    {
        public QuicheStreamIteratorSafeHandle(nint handle, bool ownsHandle = true) : base(handle, ownsHandle)
        {

        }

        public override bool IsInvalid => handle == IntPtr.Zero;

        protected override bool ReleaseHandle()
        {
            QuicheApi.QuicheStreamIterFree(this);
            SetHandle(IntPtr.Zero);
            SetHandleAsInvalid();
            return true;
        }
    }
}
