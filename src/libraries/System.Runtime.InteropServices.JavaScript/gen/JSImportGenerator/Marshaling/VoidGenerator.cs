﻿// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Runtime.InteropServices.JavaScript;

namespace Microsoft.Interop.JavaScript
{
    internal sealed class VoidGenerator(TypePositionInfo info, MarshalerType marshalerType) : BaseJSGenerator(marshalerType, new Forwarder().Bind(info))
    {
        public override IBoundMarshallingGenerator Rebind(TypePositionInfo info)
            => new VoidGenerator(info, Type);
    }
}
