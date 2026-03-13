// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Comprehensive .NET (C#) allocation test for trace-malloc
// Tests: Array, List<T>, Dictionary, String, P/Invoke native malloc, intentional leak
// .NET uses its own GC heap but P/Invoke and certain interop paths use libc malloc.
// This test exercises both managed allocations (which trigger native allocs internally)
// and explicit P/Invoke malloc/free to ensure trace-malloc captures them.

using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

class TestDotnetAllocs
{
    // P/Invoke to libc malloc/free for explicit native allocation testing
    [DllImport("libc", EntryPoint = "malloc")]
    static extern IntPtr NativeMalloc(nuint size);

    [DllImport("libc", EntryPoint = "calloc")]
    static extern IntPtr NativeCalloc(nuint nmemb, nuint size);

    [DllImport("libc", EntryPoint = "free")]
    static extern void NativeFree(IntPtr ptr);

    [DllImport("libc", EntryPoint = "realloc")]
    static extern IntPtr NativeRealloc(IntPtr ptr, nuint size);

    const int N = 10;

    static void TestPInvokeMalloc()
    {
        Console.WriteLine("=== P/Invoke malloc/free ===");
        var ptrs = new IntPtr[N];
        for (int i = 0; i < N; i++)
        {
            ptrs[i] = NativeMalloc((nuint)(1024 * (i + 1)));
            if (ptrs[i] == IntPtr.Zero)
                throw new OutOfMemoryException("malloc failed for size " + (1024 * (i + 1)));
            // Touch the memory
            Marshal.WriteByte(ptrs[i], (byte)(i & 0xFF));
        }
        for (int i = 0; i < N; i++)
            NativeFree(ptrs[i]);
    }

    static void TestPInvokeCalloc()
    {
        Console.WriteLine("=== P/Invoke calloc/free ===");
        var ptrs = new IntPtr[N];
        for (int i = 0; i < N; i++)
        {
            ptrs[i] = NativeCalloc((nuint)(100 + i * 10), 64);
            if (ptrs[i] == IntPtr.Zero)
                throw new OutOfMemoryException("calloc failed");
        }
        for (int i = 0; i < N; i++)
            NativeFree(ptrs[i]);
    }

    static void TestPInvokeRealloc()
    {
        Console.WriteLine("=== P/Invoke realloc ===");
        IntPtr p = NativeMalloc(64);
        for (int i = 0; i < N; i++)
        {
            p = NativeRealloc(p, (nuint)(64 * (i + 2)));
            if (p == IntPtr.Zero)
                throw new OutOfMemoryException("realloc failed");
        }
        NativeFree(p);
    }

    static void TestManagedArrays()
    {
        Console.WriteLine("=== Managed arrays ===");
        for (int i = 0; i < N; i++)
        {
            byte[] arr = new byte[1024 * (i + 1)];
            Array.Fill(arr, (byte)0xAA);
        }
        // Arrays go through GC, but .NET runtime uses native malloc internally
    }

    static void TestManagedList()
    {
        Console.WriteLine("=== List<int> ===");
        var list = new List<int>();
        for (int i = 0; i < 1000; i++)
            list.Add(i);
        list.Clear();
        list.TrimExcess();
    }

    static void TestManagedDictionary()
    {
        Console.WriteLine("=== Dictionary<int,string> ===");
        var dict = new Dictionary<int, string>();
        for (int i = 0; i < 100; i++)
            dict[i] = "value_" + i;
        dict.Clear();
    }

    static void TestManagedString()
    {
        Console.WriteLine("=== StringBuilder ===");
        var sb = new StringBuilder();
        for (int i = 0; i < 100; i++)
            sb.Append("hello world ");
        sb.Clear();
    }

    static void TestMarshalAlloc()
    {
        Console.WriteLine("=== Marshal.AllocHGlobal/FreeHGlobal ===");
        // Marshal.AllocHGlobal uses native malloc on Linux
        var ptrs = new IntPtr[N];
        for (int i = 0; i < N; i++)
        {
            ptrs[i] = Marshal.AllocHGlobal(1024 * (i + 1));
            Marshal.WriteByte(ptrs[i], (byte)i);
        }
        for (int i = 0; i < N; i++)
            Marshal.FreeHGlobal(ptrs[i]);
    }

    static void TestIntentionalLeak()
    {
        Console.WriteLine("=== intentional leak (P/Invoke) ===");
        // Leak native memory - GC will not collect this
        IntPtr leaked = NativeMalloc(4096);
        Marshal.WriteByte(leaked, 0x42);
        // Intentionally NOT freed
        GC.KeepAlive(leaked);
    }

    static void Main()
    {
        TestPInvokeMalloc();
        TestPInvokeCalloc();
        TestPInvokeRealloc();
        TestManagedArrays();
        TestManagedList();
        TestManagedDictionary();
        TestManagedString();
        TestMarshalAlloc();
        TestIntentionalLeak();

        // Force GC to see managed allocation patterns
        GC.Collect();
        GC.WaitForPendingFinalizers();

        Console.WriteLine("All .NET tests passed.");
    }
}
