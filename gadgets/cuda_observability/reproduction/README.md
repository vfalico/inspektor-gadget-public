# Reproducing the vLLM comparison

This bundle runs an unmodified vLLM container, GitHub Copilot CLI, and the
`cuda_observability` gadget on one Linux NVIDIA host. The gadget uses external
eBPF observation; it does not patch vLLM, CUDA, or Copilot.

The bundle is a publication rehearsal until immutable public source, image,
model, and container digests replace the local defaults. It never pushes an OCI
image.

## Reference stack

- Inspektor Gadget `v0.57.0`
- `vllm/vllm-openai:v0.10.2`
- `Qwen/Qwen2.5-0.5B-Instruct`
- GitHub Copilot CLI `1.0.65`
- one GPU, sequential traffic, `max-num-seqs=1`, eager execution
- transition-v4 A100/Qwen/vLLM preset

The reported T-758 values were measured on an A100 80GB. Other GPUs are useful
for functional testing but are not expected to reproduce the same agreement.

## Local image rehearsal

Build the gadget from the repository root:

```bash
export IG_SOURCE_PATH=$PWD
export SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)
sudo -E ig image build \
  gadgets/cuda_observability \
  -t localhost/cuda_observability:reproduction
```

Export it without publishing:

```bash
sudo ig image export \
  localhost/cuda_observability:reproduction \
  cuda_observability-reproduction.tar
sha256sum cuda_observability-reproduction.tar
```

On another host, copy the archive and load it:

```bash
sudo ig image import cuda_observability-reproduction.tar
```

## Run

The runner refuses occupied ports, pre-existing containers, competing GPU
processes, missing local images, unexpected IG or Copilot versions, or
unavailable passwordless sudo. Container runs use `--pull=never`.

```bash
cd gadgets/cuda_observability/reproduction
./reproduce.sh preflight
./reproduce.sh smoke
./reproduce.sh canary
./reproduce.sh five-minute
```

Use environment variables to select local paths:

```bash
export REPRO_IG_BIN=/path/to/ig
export REPRO_COPILOT_BIN=/path/to/copilot
export REPRO_MODEL_CACHE=/path/to/huggingface-cache
export REPRO_GADGET_IMAGE=localhost/cuda_observability:reproduction
export REPRO_GPU_DEVICE=0
```

`REPRO_GADGET_IMAGE` also accepts an immutable reference such as
`ghcr.io/vfalico/cuda_observability@sha256:<manifest>`.

The default `REPRO_IG_SCOPE=host` is required for the tested released
`ig v0.57.0` binary. The runner starts IG, waits until the heuristic analyzer is
ready, and only then starts vLLM so every CUDA library and EngineCore process is
observed from birth. Host scope is valid only when preflight confirms that no
other CUDA process is present; that process-isolation gate is the attribution
boundary.

`REPRO_IG_SCOPE=container` remains available for IG builds that can discover
CUDA children which already exist inside the selected container. It is not the
validated v0.57.0 reproduction path.

Each run preserves paired raw Prometheus snapshots, IG JSONL output, Copilot
output, logs, CSVs, SVGs, a summary, and portable relative-path checksums. The
collector checks GPU process ownership on every scrape, and integrity validation
independently rejects measured raw CUDA events from outside the vLLM container.
Analysis uses adjacent five-second histogram deltas:

```text
window mean = delta(histogram_sum) / delta(histogram_count)
```

It does not compare cumulative averages or interpolate missing windows.
It rejects excessive within-pair skew, slow scrapes, interval drift, TTFT count
mismatch, and severe ITL candidate/native count divergence.

Model initialization can produce CUDA activity and analyzer diagnostics before
the measured workload starts. Integrity validation reports those events
separately as pre-measurement diagnostics; any analyzer-health event at or after
the first measured Copilot turn still fails the run.

## Interpretation

The native series are vLLM TTFT and tokenizer-token ITL. The gadget series are
an IG CUDA gadget TTFT candidate and decode-interval candidate. They are
correlates, not CUDA-native semantic TTFT or token latency.

A poor answer from Qwen does not invalidate a timing run. A valid run requires
completed provider traffic, aligned metric windows, no unexplained competing
GPU process, and zero authoritative gadget loss or failure counters.

This comparison does not measure observer overhead. That requires a separate
attached-versus-unattached experiment.
