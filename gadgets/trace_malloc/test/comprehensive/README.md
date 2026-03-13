# trace-malloc Comprehensive Tests

## Overview

Comprehensive tests for the trace-malloc gadget covering 4 programming languages:
- **C** — All libc allocation functions (malloc, calloc, realloc, mmap, posix_memalign, memalign, etc.)
- **C++** — new/delete, STL containers (vector, string, map), smart pointers
- **Rust** — Vec, Box, String, HashMap, mem::forget leaks
- **.NET (C#)** — P/Invoke malloc/calloc/realloc, Marshal.AllocHGlobal, managed containers

Each test includes an intentional memory leak to verify leak detection capabilities.

## Directory Structure

```
comprehensive/
├── ANALYSIS.md                    # Full analysis and comparison with heaptrack
├── README.md                      # This file
├── testdata/                      # Test source code
│   ├── test_c_allocs.c
│   ├── test_cpp_allocs.cpp
│   ├── test_rust_allocs.rs
│   └── test_dotnet_allocs.cs
├── scripts/
│   ├── run_tests.sh               # Main test runner (builds + runs all 4 languages)
│   ├── run_overhead.sh            # Overhead benchmark script
│   └── convert_trace_malloc_to_heaptrack.py  # JSON → heaptrack format converter
├── results/                       # Full test outputs
│   ├── c/
│   │   ├── trace_malloc_output.json
│   │   └── converted.heaptrack
│   ├── cpp/
│   │   ├── trace_malloc_output.json
│   │   └── converted.heaptrack
│   ├── rust/
│   │   ├── trace_malloc_output.json
│   │   └── converted.heaptrack
│   ├── dotnet/
│   │   ├── trace_malloc_output.json
│   │   └── converted.heaptrack
│   └── overhead/
│       └── overhead_report.txt
└── examples/                      # Small sample files for quick GUI testing
    ├── c_sample.json / c_sample.heaptrack
    ├── cpp_sample.json / cpp_sample.heaptrack
    ├── rust_sample.json / rust_sample.heaptrack
    └── dotnet_sample.json / dotnet_sample.heaptrack
```

## Quick Start

### Run tests
```bash
# Build test programs (requires gcc, g++, rustc, dotnet SDK 8.0+)
gcc -O2 -o /tmp/test_c_allocs testdata/test_c_allocs.c
g++ -O2 -o /tmp/test_cpp_allocs testdata/test_cpp_allocs.cpp
rustc -O -o /tmp/test_rust_allocs testdata/test_rust_allocs.rs
# For .NET: dotnet publish -c Release -r linux-x64 --self-contained

# Run trace-malloc + test binary
ig run trace_malloc:latest --host --verify-image=false --timeout 30 -o json > output.json &
sleep 3 && /tmp/test_c_allocs && sleep 2 && kill %1
```

### Convert to heaptrack format
```bash
python3 scripts/convert_trace_malloc_to_heaptrack.py -i output.json -o output.heaptrack
heaptrack_print output.heaptrack  # Verify
```

### Quick test with examples
```bash
heaptrack_print examples/c_sample.heaptrack
heaptrack_print examples/dotnet_sample.heaptrack
```

## Key Findings

See [ANALYSIS.md](ANALYSIS.md) for full analysis. Summary:

- trace-malloc captures events from all 4 languages correctly
- Lower overhead than heaptrack for native code (250-530% vs 3310-4980%)
- Higher overhead for .NET due to ~30K internal runtime allocations
- JSON → heaptrack converter works; heaptrack_print validates all outputs
- The two tools are complementary: trace-malloc for system-wide observability, heaptrack for deep single-process analysis
