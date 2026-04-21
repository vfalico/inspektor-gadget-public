# gpu_mem_max

Deterministic GPU VRAM high-water-mark tracker.

Combines uprobes on `libcuda.so:cuMemAlloc_v2 / cuMemAllocManaged /
cuMemFree_v2` (per-container attribution) with an NVML poller (ground
truth) and emits three datasources:

* `allocs`    — per-event stream
* `snapshots` — 10 Hz NVML memory snapshots (timeseries chart)
* `summary`   — per-container MAX_REPORT + SIGNAL_LOSS diagnostics

## Usage

```
sudo ig image build -t gpu_mem_max:v0 ./gadgets/gpu_mem_max
sudo ig run gpu_mem_max:v0 --host -o json
```

## Three-axis oracle

The gadget reports three orthogonal numbers per container so users can
diagnose whether any BPF-vs-NVML gap is signal loss or driver-context
overhead:

* `bpf_delta_bytes`   — Σ(ALLOC.size - FREE.size) from uprobes
* `nvml_delta_bytes`  — NVML peak_used − baseline_used
* `torch_delta_bytes` — for PyTorch workloads, consumer's own
                        `torch.cuda.max_memory_reserved()`

The signal-loss threshold defaults to 5 % (A100 context overhead is
legitimately ~0.4–0.7 % of 80 GB; 2 % would false-trigger every run).
