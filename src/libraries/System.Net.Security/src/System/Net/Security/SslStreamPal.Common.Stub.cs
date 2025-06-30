// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Threading;
using System.Threading.Tasks;

namespace System.Net.Security;

internal static partial class SslStreamPal
{
    internal const bool UseAsyncDecrypt = false;
    public static void GetPendingWriteData(SafeDeleteContext _, ref ProtocolToken _1) => throw new PlatformNotSupportedException();

    public static int GetAvailableDecryptedBytes(SafeDeleteContext _) => throw new PlatformNotSupportedException();

    public static int ReadDecryptedData(SafeDeleteContext _, Span<byte> _1) => throw new PlatformNotSupportedException();

    public static Task<SecurityStatusPalErrorCode>? ExtractHandshakeTask(SafeFreeCredentials _, SafeDeleteContext _1) => throw new PlatformNotSupportedException();

    public static Task<SecurityStatusPalErrorCode>? ExtractDecryptionTask(SafeDeleteContext _) => throw new PlatformNotSupportedException();

    internal static bool SupportsAsyncOperations(SafeDeleteContext? _)
    {
        return UseAsyncDecrypt;
    }
}
