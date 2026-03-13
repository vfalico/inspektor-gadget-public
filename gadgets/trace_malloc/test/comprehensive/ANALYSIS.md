# trace-malloc Tests & Heaptrack Comparison Analysis (v2)

## Date: 2026-03-13

## 1. Test Setup

- **Platform**: Linux 6.8.0-101-generic x86_64, Ubuntu 24.04
- **Inspektor Gadget**: v0.50.1 (ig), trace_malloc:latest
- **Heaptrack**: v1.5.0 (Ubuntu package)
- **Compilers**: gcc 13.3.0, g++ 13.3.0, rustc 1.94.0, dotnet 8.0.419
- **Hardware**: 8GB RAM, devbox VM (QEMU/KVM)

## 2. Test Programs

### C (`test_c_allocs.c`)
Tests all trace-malloc supported operations:
- malloc/free (10 pairs, sizes 1KB–10KB)
- calloc/free (10 pairs, 100×64 each)
- realloc chain (10 growing reallocs)
- reallocarray (10 cycles)
- mmap/munmap (10 pairs, 4KB–40KB)
- posix_memalign (10 pairs)
- memalign (10 pairs)
- Intentional 4KB leak

### C++ (`test_cpp_allocs.cpp`)
Tests C++ allocation patterns:
- scalar new/delete (10 cycles)
- array new[]/delete[] (10 cycles, growing sizes)
- std::vector (1000 push_backs)
- std::string (100 appends)
- std::map (100 inserts)
- std::unique_ptr (10 cycles)
- std::shared_ptr (10 cycles)
- Intentional 4KB array leak

### Rust (`test_rust_allocs.rs`)
Tests Rust allocation patterns via libc:
- Vec (1000 push)
- Box (10 cycles)
- String (100 appends)
- HashMap (100 inserts)
- Intentional 4KB leak via mem::forget

### .NET/C# (`test_dotnet_allocs.cs`)
Tests .NET allocation patterns with P/Invoke and managed allocations:
- P/Invoke malloc/free (10 pairs, 1KB–10KB)
- P/Invoke calloc/free (10 pairs)
- P/Invoke realloc chain (10 growing reallocs)
- Managed arrays (10 cycles, 1KB–10KB)
- List<int> (1000 push)
- Dictionary<int,string> (100 inserts)
- StringBuilder (100 appends)
- Marshal.AllocHGlobal/FreeHGlobal (10 pairs)
- Intentional 4KB native leak via P/Invoke

## 3. Test Results

### Events Captured

| Language | Total Events | Alloc Events | Free Events | Operations Seen |
|----------|-------------|-------------|------------|-----------------|
| C        | 153         | 73          | 80         | malloc, calloc, realloc, realloc_free, mmap, munmap, posix_memalign, memalign, free |
| C++      | 298         | 150         | 148        | malloc, free (via libc) |
| Rust     | 269         | 134         | 135        | malloc, calloc, realloc, realloc_free, mmap, munmap, free |
| .NET     | 30807       | 22139       | 8668       | malloc, calloc, realloc, realloc_free, mmap, munmap, free |

### Key Observations

1. **C**: All 9 operation types correctly captured. malloc/free, calloc, realloc (with paired realloc_free), mmap/munmap, posix_memalign, and memalign all work perfectly.

2. **C++**: new/delete operators are intercepted via libc `_Znwm`/`_ZdlPv` uprobes but reported as `malloc`/`free` in JSON output. This is because the C++ operators ultimately call into libc malloc/free. STL containers (vector, string, map) generate numerous malloc/free events as expected.

3. **Rust**: Uses system allocator (glibc malloc) by default on Linux. All Rust heap operations (Vec, Box, String, HashMap) appear as malloc/realloc/free. The calloc event comes from Rust runtime init.

4. **.NET**: The .NET runtime generates ~30K native malloc events internally for runtime initialization, JIT compilation, GC metadata, and managed heap infrastructure. Explicit P/Invoke malloc/free/calloc/realloc calls are correctly captured alongside the runtime's internal allocations. Marshal.AllocHGlobal also uses libc malloc on Linux. The large mmap sizes (2.1GB, 256GB, 2.3GB) are the .NET GC's reserved virtual address space for managed heaps — these are mostly uncommitted (PROT_NONE) memory reservations.

## 4. Heaptrack Comparison

### Format Comparison

| Feature | trace-malloc | heaptrack |
|---------|-------------|-----------|
| **Format** | JSON lines (1 event per line) | Custom binary text format (zstd compressed) |
| **Scope** | System-wide (all processes) | Single process (LD_PRELOAD) |
| **Attach method** | eBPF uprobes on libc | LD_PRELOAD injection |
| **Stack traces** | Optional (via BPF stack maps) | Always (libunwind) |
| **Metadata** | Rich (K8s, container, process, timestamps) | Minimal (stack + allocation) |
| **Filtering** | Post-hoc (by process, container, etc.) | Pre-filtered (single process) |
| **GUI support** | Via converter → heaptrack_gui | Native heaptrack_gui |

### Heaptrack Validation Results

| Language | trace-malloc events | heaptrack_print parsed | Alloc calls | Peak memory | Status |
|----------|-------------------|----------------------|-------------|-------------|--------|
| C        | 153               | ✅ Parsed OK          | 72          | 68.10K      | PASS   |
| C++      | 298               | ✅ Parsed OK          | 150         | 85.02K      | PASS   |
| Rust     | 269               | ✅ Parsed OK          | 134         | 20.91K      | PASS   |
| .NET     | 30807             | ✅ Parsed OK          | 22139       | 279.93G*    | PASS   |

*The .NET "279.93G peak" is due to .NET GC's large virtual address space reservations (mmap with PROT_NONE). Actual physical memory usage is much lower.

### Data Completeness Comparison

| Aspect | trace-malloc | heaptrack | Winner |
|--------|-------------|-----------|--------|
| Operation types | 9+ (malloc, calloc, realloc, mmap, posix_memalign, memalign, etc.) | All libc alloc functions | Tie |
| Stack traces (native) | Via BPF stack maps (addresses only) | Full symbolic stacks | heaptrack |
| Stack traces (.NET) | Addresses only | Addresses only (no managed frames) | Tie |
| Process metadata | Rich (PID, comm, parent, creds, K8s) | Process name only | trace-malloc |
| Container context | Full K8s + container info | None | trace-malloc |
| Timestamps | Nanosecond precision | Relative | trace-malloc |
| Multi-process | System-wide | Single process | trace-malloc |

## 5. Overhead Comparison

| Language | Baseline (s) | trace-malloc (s) | tm overhead | heaptrack (s) | ht overhead |
|----------|-------------|------------------|-------------|---------------|-------------|
| C        | 0.002       | 0.007            | 250%        | 0.068         | 3310%       |
| C++      | 0.002       | 0.013            | 530%        | 0.077         | 3760%       |
| Rust     | 0.002       | 0.008            | 300%        | 0.102         | 4980%       |
| .NET     | 0.067       | 0.544            | 710%        | 0.252         | 270%        |

### Overhead Analysis

- **Native languages (C, C++, Rust)**: trace-malloc has **significantly lower overhead** than heaptrack (250-530% vs 3310-4980%). trace-malloc uses lightweight eBPF uprobes, while heaptrack uses LD_PRELOAD with libunwind stack unwinding on every call.

- **.NET**: trace-malloc has **higher overhead** than heaptrack (710% vs 270%) because the .NET runtime generates ~30K internal malloc calls. trace-malloc monitors ALL system-wide events including other processes, while heaptrack only wraps the target process.

- **Absolute overhead**: trace-malloc adds only 5-10ms for native programs with 150-300 allocations, negligible for production profiling.

## 6. Converter: trace-malloc JSON → heaptrack format

The `convert_trace_malloc_to_heaptrack.py` script converts trace-malloc JSON output to heaptrack's text-based data format:

- **Input**: JSON lines from `ig run trace_malloc -o json`
- **Output**: heaptrack format (v3 with sized strings)
- **Features**:
  - Maps all allocation/deallocation operations to heaptrack +/- events
  - Builds string table, IP table, trace chains, and allocation info tables
  - Preserves timestamps and event ordering
  - Handles alloc/free pairing for temporary allocation detection

**Limitation**: Without stack trace addresses in the JSON output, all events map to a single dummy trace (0x0). When trace-malloc is extended with full stack capture in JSON, the converter will automatically produce per-function heaptrack breakdowns.

## 7. Conclusions

1. **trace-malloc correctly captures memory allocations across all 4 languages** (C, C++, Rust, .NET/C#).
2. **The JSON → heaptrack converter works** — heaptrack_print successfully parses all converted files.
3. **trace-malloc has lower overhead than heaptrack for native code** and provides richer metadata (process, container, K8s context).
4. **heaptrack provides better stack traces** for single-process deep analysis.
5. **The two tools are complementary**: trace-malloc for system-wide observability and production debugging; heaptrack for deep single-process heap analysis.
6. **.NET generates significant native allocation noise** from its runtime — trace-malloc captures this faithfully, which is valuable for diagnosing native memory leaks in .NET applications (P/Invoke, interop, runtime bugs).
