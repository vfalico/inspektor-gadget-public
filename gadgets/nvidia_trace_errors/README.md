# nvidia_trace_errors

Unified tracer for NVIDIA GPU errors — both CUDA Driver API failures (from
user-space `libcuda.so` via uprobes) and in-kernel XID events (from the
NVIDIA kernel module via a kprobe on `nv_report_error`). Every event is
enriched with a human-readable name, a one-line explanation, an actionable
suggestion, and a severity/category label — all computed at runtime by a WASM
enricher with no filesystem access.

## When to use it

| Symptom | This gadget reports |
|---|---|
| `RuntimeError: CUDA error: ...` in Python / C++ | The exact `CUresult` + the API it came from + the args |
| `dmesg` line `NVRM: Xid (PCI:...): 13, ...` | Same information, structured, with PCI address |
| `compute-sanitizer memcheck` too slow for prod | Realtime, eBPF-only, near-zero overhead |

## Events

All events share the common IG fields (`timestamp`, `proc.{pid,comm,tid}`,
container metadata) plus:

| Field | Type | Description |
|---|---|---|
| `source` | enum | `SOURCE_CUDA_API` or `SOURCE_XID` |
| `error_code` | enum | CUDA `CUresult` name (e.g. `CUDA_ERROR_OUT_OF_MEMORY`). Populated for CUDA API events only. |
| `api_id` | enum | CUDA Driver API name (e.g. `cuMemAlloc_v2`). Populated for CUDA API events only. |
| `xid_code` | uint32 | NVIDIA XID number. Populated for XID events only. |
| `gpu_pci_addr` | string | PCI address `DDDD:BB:SS.F` of the GPU that reported the XID. |
| `severity` | string | `LOW` / `MEDIUM` / `HIGH` / `CRITICAL`. |
| `category` | string | `memory`, `launch`, `context`, `device`, `hardware_ecc`, `firmware`, … |
| `description` | string | One-line plain-English explanation. |
| `why` | string | Why this happened in this context, derived from API args. |
| `suggestion` | string | Recommended remediation step. |
| `context_info` | string | Humanised argument/context details (e.g. `requested_bytes=274877906944 (256.0 GB)`). |
| `ustack` | stack | User-space call stack for CUDA API events (requires `--collect-ustack`). |

## Example

```console
$ sudo ig run nvidia_trace_errors:latest --verify-image=false \
    -o columns=pid,comm,source,error_code,xid_code,severity,why,suggestion

PID    COMM     SOURCE           ERROR_CODE                 XID  SEVERITY  WHY                                         SUGGESTION
12345  python3  SOURCE_CUDA_API  CUDA_ERROR_OUT_OF_MEMORY   0    HIGH      Allocation request 256.0 GB > free memory   Reduce batch size or use unified memory
12346  a.out    SOURCE_CUDA_API  CUDA_ERROR_INVALID_DEVICE  0    MEDIUM    Context creation on invalid ordinal=9999    Use ordinal in [0, cuDeviceGetCount())
0      swapper  SOURCE_XID       CUDA_SUCCESS               13   HIGH      Kernel executed an illegal GPU instruction  compute-sanitizer memcheck + CUDA_LAUNCH_BLOCKING=1
```

## Severity legend

| Severity | Meaning |
|---|---|
| LOW | Informational / recoverable / API misuse with no side effects |
| MEDIUM | App error requiring a code change |
| HIGH | Context-destroying error; process usually must restart |
| CRITICAL | Hardware/firmware fault; operator intervention required |

## Architecture

```
┌──────────────────┐  uprobe/uretprobe      ┌──────────────┐
│  libcuda.so      │─────────────────────▶  │ program.bpf.c│──▶ events ringbuf
│ cuMemAlloc_v2 …  │  (22 CUDA APIs)        │  save_entry/  │            │
└──────────────────┘                        │  handle_return│            ▼
                                            └──────────────┘     WASM enricher
┌──────────────────┐  kprobe                        ▲            (program.go
│  nvidia.ko       │─────────────────────────────────┘             compiled to
│  nv_report_error │  (1 in-kernel function)                        WASM)
└──────────────────┘                                                   │
                                                                       ▼
                                                              ig columns / json
```

The BPF program only emits events when `ret != CUDA_SUCCESS`; successful calls
cost one hash-map insert + one hash-map delete on the uretprobe.

## Limitations

* Only the **CUDA Driver API** is hooked directly. Errors returned by the
  higher-level Runtime API (`cudaMalloc`, `cudaLaunchKernel`) surface through
  their Driver-API callees, so they are still observed — but with the Driver
  API name, not the Runtime name.
* XID capture relies on the symbol `nv_report_error` exported by the open-
  source NVIDIA kernel module. Older proprietary-only driver builds may not
  export this symbol; the gadget still loads but no XID events will be emitted.
* The WASM enricher catalog is embedded at build time; new XID numbers or
  CUDA error codes introduced by a future driver release will be rendered as
  `XID_<n>` / `CUDA_ERROR_<n>` with an "Unknown" suggestion until the catalog
  is updated.

## See also

* [NVIDIA XID documentation](https://docs.nvidia.com/deploy/xid-errors/)
* [CUDA Driver API error codes](https://docs.nvidia.com/cuda/cuda-driver-api/group__CUDA__TYPES.html)
* `profile_cuda` gadget — for per-kernel timing, not errors.
