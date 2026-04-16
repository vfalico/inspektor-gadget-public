# cuda_error_trace

Trace CUDA Driver API errors with enriched, human-readable descriptions using eBPF and a Go WASM enricher.

## Overview

`cuda_error_trace` hooks into 22 CUDA Driver API functions via uprobes and emits an event for every non-`CUDA_SUCCESS` return. A bundled Go WASM enricher maps the raw numeric `error_code` and `api_id` fields to human-readable strings at runtime, providing:

- `error_name` — symbolic CUDA error constant (e.g. `CUDA_ERROR_OUT_OF_MEMORY`)
- `api_name` — CUDA function that returned the error (e.g. `cuMemAlloc_v2`)
- `description` — plain-English explanation
- `category` — error category (`memory`, `launch`, `context`, `module`, `device`, etc.)
- `suggestion` — actionable remediation steps
- `context_info` — API-specific argument context (e.g. `requested_bytes=8589934592 (8.0 GB)`)

## Traced APIs

| api_id | Function | Category |
|--------|----------|----------|
| 1 | cuMemAlloc_v2 | memory |
| 2 | cuMemAllocPitch_v2 | memory |
| 3 | cuMemAllocManaged | memory |
| 4 | cuLaunchKernel | launch |
| 5 | cuCtxCreate_v2 | context |
| 6 | cuDeviceGet | device |
| 7 | cuDeviceGetCount | device |
| 8 | cuModuleLoad | module |
| 9 | cuModuleLoadData | module |
| 10 | cuModuleGetFunction | module |
| 11 | cuMemcpyHtoD_v2 | memory |
| 12 | cuMemcpyDtoH_v2 | memory |
| 13 | cuStreamCreate | stream |
| 14 | cuStreamQuery | stream |
| 15 | cuStreamSynchronize | stream |
| 16 | cuEventCreate | event |
| 17 | cuEventRecord | event |
| 18 | cuEventQuery | event |
| 19 | cuEventSynchronize | event |
| 20 | cuMemFree_v2 | memory |
| 21 | cuCtxSynchronize | context |
| 22 | cuInit | init |

## Usage

```bash
# Run against all processes
sudo ig run ghcr.io/inspektor-gadget/gadget/cuda_error_trace:latest

# Filter by process name
sudo ig run ghcr.io/inspektor-gadget/gadget/cuda_error_trace:latest --filter proc.comm=train_model

# Pretty JSON output
sudo ig run ghcr.io/inspektor-gadget/gadget/cuda_error_trace:latest -o jsonpretty

# Include hidden suggestion and description fields
sudo ig run ghcr.io/inspektor-gadget/gadget/cuda_error_trace:latest \
  -o jsonpretty --fields +suggestion,+description
```

## Example Output

**Before enrichment (raw BPF output):**
```json
{
  "proc.comm": "train_model",
  "proc.pid": 12345,
  "error_code": 2,
  "api_id": 1,
  "arg1": 140234567890,
  "arg2": 8589934592,
  "arg3": 0,
  "arg4": 0,
  "arg5": 0,
  "arg6": 0
}
```

**After WASM enrichment:**
```json
{
  "proc.comm": "train_model",
  "proc.pid": 12345,
  "error_code": 2,
  "error_name": "CUDA_ERROR_OUT_OF_MEMORY",
  "api_id": 1,
  "api_name": "cuMemAlloc_v2",
  "description": "The API call failed because it was unable to allocate enough memory to perform the requested operation",
  "category": "memory",
  "suggestion": "Reduce batch size, enable gradient checkpointing, use torch.cuda.empty_cache(), use model parallelism, or use a GPU with more memory",
  "context_info": "requested_bytes=8589934592 (8.0 GB)"
}
```

## Building

### Inside the Inspektor Gadget tree

```bash
git clone https://github.com/inspektor-gadget/inspektor-gadget.git
cd inspektor-gadget
# Apply patches
git am patches/0001-gadgets-cuda_error_trace-add-eBPF-program.patch
git am patches/0002-gadgets-cuda_error_trace-add-gadget-metadata.patch
git am patches/0003-gadgets-cuda_error_trace-add-WASM-enricher.patch
git am patches/0004-gadgets-cuda_error_trace-add-build-config.patch
git am patches/0005-gadgets-cuda_error_trace-add-README.patch
git am patches/0006-gadgets-cuda_error_trace-add-ArtifactHub-metadata.patch
# Build
sudo ig image build gadgets/cuda_error_trace -t cuda_error_trace:latest
```

### Standalone (out-of-tree)

```bash
# Prerequisites: ig installed, Docker available
cp -r gadgets/cuda_error_trace /tmp/cuda_error_trace
cd /tmp/cuda_error_trace/go
go mod tidy   # fetches inspektor-gadget WASM API
cd ..
sudo ig image build . -t cuda_error_trace:latest
sudo ig run cuda_error_trace:latest --verify-image=false
```

## Error Code Reference

| Code | Name | Category |
|------|------|----------|
| 1 | CUDA_ERROR_INVALID_VALUE | parameter |
| 2 | CUDA_ERROR_OUT_OF_MEMORY | memory |
| 3 | CUDA_ERROR_NOT_INITIALIZED | init |
| 4 | CUDA_ERROR_DEINITIALIZED | init |
| 5 | CUDA_ERROR_PROFILER_DISABLED | profiler |
| 9 | CUDA_ERROR_STUB_LIBRARY | init |
| 34 | CUDA_ERROR_NO_DEVICE | device |
| 35 | CUDA_ERROR_INVALID_DEVICE | device |
| 36 | CUDA_ERROR_DEVICE_NOT_LICENSED | device |
| 46 | CUDA_ERROR_INVALID_IMAGE | module |
| 48 | CUDA_ERROR_INVALID_CONTEXT | context |
| 49 | CUDA_ERROR_CONTEXT_ALREADY_CURRENT | context |
| 54 | CUDA_ERROR_MAP_FAILED | memory |
| 55 | CUDA_ERROR_UNMAP_FAILED | memory |
| 56 | CUDA_ERROR_ARRAY_IS_MAPPED | memory |
| 57 | CUDA_ERROR_ALREADY_MAPPED | memory |
| 58 | CUDA_ERROR_NO_BINARY_FOR_GPU | module |
| 59 | CUDA_ERROR_ALREADY_ACQUIRED | memory |
| 60 | CUDA_ERROR_NOT_MAPPED | memory |
| 61 | CUDA_ERROR_NOT_MAPPED_AS_ARRAY | memory |
| 62 | CUDA_ERROR_NOT_MAPPED_AS_POINTER | memory |
| 63 | CUDA_ERROR_ECC_UNCORRECTABLE | hardware |
| 64 | CUDA_ERROR_UNSUPPORTED_LIMIT | resource |
| 65 | CUDA_ERROR_CONTEXT_ALREADY_IN_USE | context |
| 66 | CUDA_ERROR_PEER_ACCESS_UNSUPPORTED | peer |
| 67 | CUDA_ERROR_INVALID_PTX | module |
| 68 | CUDA_ERROR_INVALID_GRAPHICS_CONTEXT | interop |
| 69 | CUDA_ERROR_NVLINK_UNCORRECTABLE | hardware |
| 700 | CUDA_ERROR_ILLEGAL_ADDRESS | memory |
| 999 | CUDA_ERROR_UNKNOWN | unknown |

## Requirements

- Linux kernel ≥ 5.10 (uprobe + ring buffer support)
- NVIDIA CUDA Driver installed (`libcuda.so` present)
- `ig` (Inspektor Gadget) v0.33.0+
- Docker (for `ig image build`)
