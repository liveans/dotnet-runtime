// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics;
using System.Runtime.InteropServices;

namespace System.Runtime.CompilerServices
{
    [StackTraceHidden]
    [DebuggerStepThrough]
    internal static unsafe class CastHelpers
    {
        // In coreclr the table is allocated and written to on the native side.
        internal static int[]? s_table;

        [MethodImpl(MethodImplOptions.InternalCall)]
        private static extern object IsInstanceOfAny_NoCacheLookup(void* toTypeHnd, object obj);

        [MethodImpl(MethodImplOptions.InternalCall)]
        private static extern object ChkCastAny_NoCacheLookup(void* toTypeHnd, object obj);

        [MethodImpl(MethodImplOptions.InternalCall)]
        private static extern ref byte Unbox_Helper(void* toTypeHnd, object obj);

        [MethodImpl(MethodImplOptions.InternalCall)]
        private static extern void WriteBarrier(ref object? dst, object? obj);

        // IsInstanceOf test used for unusual cases (naked type parameters, variant generic types)
        // Unlike the IsInstanceOfInterface and IsInstanceOfClass functions,
        // this test must deal with all kinds of type tests
        [DebuggerHidden]
        private static object? IsInstanceOfAny(void* toTypeHnd, object? obj)
        {
            if (obj != null)
            {
                void* mt = RuntimeHelpers.GetMethodTable(obj);
                if (mt != toTypeHnd)
                {
                    CastResult result = CastCache.TryGet(s_table!, (nuint)mt, (nuint)toTypeHnd);
                    if (result == CastResult.CanCast)
                    {
                        // do nothing
                    }
                    else if (result == CastResult.CannotCast)
                    {
                        obj = null;
                    }
                    else
                    {
                        goto slowPath;
                    }
                }
            }

            return obj;

        slowPath:
            // fall through to the slow helper
            return IsInstanceOfAny_NoCacheLookup(toTypeHnd, obj);
        }

        [DebuggerHidden]
        private static object? IsInstanceOfInterface(void* toTypeHnd, object? obj)
        {
            const int unrollSize = 4;

            if (obj != null)
            {
                MethodTable* mt = RuntimeHelpers.GetMethodTable(obj);
                nint interfaceCount = mt->InterfaceCount;
                if (interfaceCount != 0)
                {
                    MethodTable** interfaceMap = mt->InterfaceMap;
                    if (interfaceCount < unrollSize)
                    {
                        // If not enough for unrolled, jmp straight to small loop
                        // as we already know there is one or more interfaces so don't need to check again.
                        goto few;
                    }

                    do
                    {
                        if (interfaceMap[0] == toTypeHnd ||
                            interfaceMap[1] == toTypeHnd ||
                            interfaceMap[2] == toTypeHnd ||
                            interfaceMap[3] == toTypeHnd)
                        {
                            goto done;
                        }

                        interfaceMap += unrollSize;
                        interfaceCount -= unrollSize;
                    } while (interfaceCount >= unrollSize);

                    if (interfaceCount == 0)
                    {
                        // If none remaining, skip the short loop
                        goto extra;
                    }

                few:
                    do
                    {
                        if (interfaceMap[0] == toTypeHnd)
                        {
                            goto done;
                        }

                        // Assign next offset
                        interfaceMap++;
                        interfaceCount--;
                    } while (interfaceCount > 0);
                }

            extra:
                if (mt->NonTrivialInterfaceCast)
                {
                    goto slowPath;
                }

                obj = null;
            }

        done:
            return obj;

        slowPath:
            return IsInstance_Helper(toTypeHnd, obj);
        }

        [DebuggerHidden]
        private static object? IsInstanceOfClass(void* toTypeHnd, object? obj)
        {
            if (obj == null || RuntimeHelpers.GetMethodTable(obj) == toTypeHnd)
                return obj;

            MethodTable* mt = RuntimeHelpers.GetMethodTable(obj)->ParentMethodTable;
            for (; ; )
            {
                if (mt == toTypeHnd)
                    goto done;

                if (mt == null)
                    break;

                mt = mt->ParentMethodTable;
                if (mt == toTypeHnd)
                    goto done;

                if (mt == null)
                    break;

                mt = mt->ParentMethodTable;
                if (mt == toTypeHnd)
                    goto done;

                if (mt == null)
                    break;

                mt = mt->ParentMethodTable;
                if (mt == toTypeHnd)
                    goto done;

                if (mt == null)
                    break;

                mt = mt->ParentMethodTable;
            }

            // this helper is not supposed to be used with type-equivalent "to" type.
            Debug.Assert(!((MethodTable*)toTypeHnd)->HasTypeEquivalence);

            obj = null;

        done:
            return obj;
        }

        [DebuggerHidden]
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static object? IsInstance_Helper(void* toTypeHnd, object obj)
        {
            CastResult result = CastCache.TryGet(s_table!, (nuint)RuntimeHelpers.GetMethodTable(obj), (nuint)toTypeHnd);
            if (result == CastResult.CanCast)
            {
                return obj;
            }
            else if (result == CastResult.CannotCast)
            {
                return null;
            }

            // fall through to the slow helper
            return IsInstanceOfAny_NoCacheLookup(toTypeHnd, obj);
        }

        // ChkCast test used for unusual cases (naked type parameters, variant generic types)
        // Unlike the ChkCastInterface and ChkCastClass functions,
        // this test must deal with all kinds of type tests
        [DebuggerHidden]
        internal static object? ChkCastAny(void* toTypeHnd, object? obj)
        {
            CastResult result;

            if (obj != null)
            {
                void* mt = RuntimeHelpers.GetMethodTable(obj);
                if (mt != toTypeHnd)
                {
                    result = CastCache.TryGet(s_table!, (nuint)mt, (nuint)toTypeHnd);
                    if (result != CastResult.CanCast)
                    {
                        goto slowPath;
                    }
                }
            }

            return obj;

        slowPath:
            // fall through to the slow helper
            object objRet = ChkCastAny_NoCacheLookup(toTypeHnd, obj);
            // Make sure that the fast helper have not lied
            Debug.Assert(result != CastResult.CannotCast);
            return objRet;
        }

        [DebuggerHidden]
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static object? ChkCast_Helper(void* toTypeHnd, object obj)
        {
            CastResult result = CastCache.TryGet(s_table!, (nuint)RuntimeHelpers.GetMethodTable(obj), (nuint)toTypeHnd);
            if (result == CastResult.CanCast)
            {
                return obj;
            }

            // fall through to the slow helper
            return ChkCastAny_NoCacheLookup(toTypeHnd, obj);
        }

        [DebuggerHidden]
        private static object? ChkCastInterface(void* toTypeHnd, object? obj)
        {
            const int unrollSize = 4;

            if (obj != null)
            {
                MethodTable* mt = RuntimeHelpers.GetMethodTable(obj);
                nint interfaceCount = mt->InterfaceCount;
                if (interfaceCount == 0)
                {
                    goto slowPath;
                }

                MethodTable** interfaceMap = mt->InterfaceMap;
                if (interfaceCount < unrollSize)
                {
                    // If not enough for unrolled, jmp straight to small loop
                    // as we already know there is one or more interfaces so don't need to check again.
                    goto few;
                }

                do
                {
                    if (interfaceMap[0] == toTypeHnd ||
                        interfaceMap[1] == toTypeHnd ||
                        interfaceMap[2] == toTypeHnd ||
                        interfaceMap[3] == toTypeHnd)
                    {
                        goto done;
                    }

                    // Assign next offset
                    interfaceMap += unrollSize;
                    interfaceCount -= unrollSize;
                } while (interfaceCount >= unrollSize);

                if (interfaceCount == 0)
                {
                    // If none remaining, skip the short loop
                    goto slowPath;
                }

            few:
                do
                {
                    if (interfaceMap[0] == toTypeHnd)
                    {
                        goto done;
                    }

                    // Assign next offset
                    interfaceMap++;
                    interfaceCount--;
                } while (interfaceCount > 0);

                goto slowPath;
            }

        done:
            return obj;

        slowPath:
            return ChkCast_Helper(toTypeHnd, obj);
        }

        [DebuggerHidden]
        private static object? ChkCastClass(void* toTypeHnd, object? obj)
        {
            if (obj == null || RuntimeHelpers.GetMethodTable(obj) == toTypeHnd)
            {
                return obj;
            }

            return ChkCastClassSpecial(toTypeHnd, obj);
        }

        // Optimized helper for classes. Assumes that the trivial cases
        // has been taken care of by the inlined check
        [DebuggerHidden]
        private static object? ChkCastClassSpecial(void* toTypeHnd, object obj)
        {
            MethodTable* mt = RuntimeHelpers.GetMethodTable(obj);
            Debug.Assert(mt != toTypeHnd, "The check for the trivial cases should be inlined by the JIT");

            for (; ; )
            {
                mt = mt->ParentMethodTable;
                if (mt == toTypeHnd)
                    goto done;

                if (mt == null)
                    break;

                mt = mt->ParentMethodTable;
                if (mt == toTypeHnd)
                    goto done;

                if (mt == null)
                    break;

                mt = mt->ParentMethodTable;
                if (mt == toTypeHnd)
                    goto done;

                if (mt == null)
                    break;

                mt = mt->ParentMethodTable;
                if (mt == toTypeHnd)
                    goto done;

                if (mt == null)
                    break;
            }

            goto slowPath;

        done:
            return obj;

        slowPath:
            return ChkCast_Helper(toTypeHnd, obj);
        }

        [DebuggerHidden]
        private static ref byte Unbox(void* toTypeHnd, object obj)
        {
            // This will throw NullReferenceException if obj is null.
            if (RuntimeHelpers.GetMethodTable(obj) == toTypeHnd)
                return ref obj.GetRawData();

            return ref Unbox_Helper(toTypeHnd, obj);
        }

        [DebuggerHidden]
        private static void ThrowIndexOutOfRangeException()
        {
            throw new IndexOutOfRangeException();
        }

        [DebuggerHidden]
        private static void ThrowArrayMismatchException()
        {
            throw new ArrayTypeMismatchException();
        }

        [DebuggerHidden]
        private static ref object? LdelemaRef(object?[] array, nint index, void* type)
        {
            // This will throw NullReferenceException if array is null.
            if ((nuint)index >= (uint)array.Length)
                ThrowIndexOutOfRangeException();

            Debug.Assert(index >= 0);
            ref object? element = ref Unsafe.Add(ref MemoryMarshal.GetArrayDataReference(array), index);
            void* elementType = RuntimeHelpers.GetMethodTable(array)->ElementType;

            if (elementType != type)
                ThrowArrayMismatchException();

            return ref element;
        }

        [DebuggerHidden]
        private static void StelemRef(object?[] array, nint index, object? obj)
        {
            // This will throw NullReferenceException if array is null.
            if ((nuint)index >= (uint)array.Length)
                ThrowIndexOutOfRangeException();

            Debug.Assert(index >= 0);
            ref object? element = ref Unsafe.Add(ref MemoryMarshal.GetArrayDataReference(array), index);
            void* elementType = RuntimeHelpers.GetMethodTable(array)->ElementType;

            if (obj == null)
                goto assigningNull;

            if (elementType != RuntimeHelpers.GetMethodTable(obj))
                goto notExactMatch;

            doWrite:
                WriteBarrier(ref element, obj);
                return;

            assigningNull:
                element = null;
                return;

            notExactMatch:
                if (array.GetType() == typeof(object[]))
                    goto doWrite;

            StelemRef_Helper(ref element, elementType, obj);
        }

        [DebuggerHidden]
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static void StelemRef_Helper(ref object? element, void* elementType, object obj)
        {
            CastResult result = CastCache.TryGet(s_table!, (nuint)RuntimeHelpers.GetMethodTable(obj), (nuint)elementType);
            if (result == CastResult.CanCast)
            {
                WriteBarrier(ref element, obj);
                return;
            }

            StelemRef_Helper_NoCacheLookup(ref element, elementType, obj);
        }

        [DebuggerHidden]
        private static void StelemRef_Helper_NoCacheLookup(ref object? element, void* elementType, object obj)
        {
            Debug.Assert(obj != null);

            obj = IsInstanceOfAny_NoCacheLookup(elementType, obj);
            if (obj == null)
            {
                ThrowArrayMismatchException();
            }

            WriteBarrier(ref element, obj);
        }
    }
}
