#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# bench/run_overhead.sh — paired measurement of gadget overhead on the
# nvidia_trace_errors uprobed hot path.
set -euo pipefail
K="${K:-10}"
N="${N:-2000}"
WORK="${WORK:-8192}"
OUT="${OUT:-evidence/overhead_hotpath.json}"
BENCH="${BENCH:-bench/cuda_hotpath_bench}"
GADGET_IMG="${GADGET_IMG:-ghcr.io/inspektor-gadget/gadget/nvidia_trace_errors:latest}"
CORE="${CORE:-4}"

mkdir -p evidence bench

{
  echo "ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "kernel=$(uname -r)"
  nvidia-smi --query-gpu=name,driver_version --format=csv
  echo "---compute-apps---"
  nvidia-smi --query-compute-apps=pid,process_name,used_memory --format=csv
  echo "---cpu governor (cpu${CORE})---"
  cat /sys/devices/system/cpu/cpu${CORE}/cpufreq/scaling_governor 2>/dev/null || echo "n/a"
  echo "---bench params---"
  echo "K=$K N=$N WORK=$WORK CORE=$CORE"
} > evidence/overhead_preflight.txt

: > evidence/overhead_baseline_hp.jsonl
for i in $(seq 1 "$K"); do
  taskset -c "$CORE" "$BENCH" "$N" "$WORK" >> evidence/overhead_baseline_hp.jsonl
done

sudo -n kubectl gadget run "$GADGET_IMG" \
     -o jsonpretty --timeout=600 > evidence/overhead_gadget_trace.log 2>&1 &
GADGET_PID=$!
sleep 15   # uprobe attachment settle

: > evidence/overhead_withgadget_hp.jsonl
for i in $(seq 1 "$K"); do
  taskset -c "$CORE" "$BENCH" "$N" "$WORK" >> evidence/overhead_withgadget_hp.jsonl
done

sudo -n kill -TERM "$GADGET_PID" 2>/dev/null || true
wait "$GADGET_PID" 2>/dev/null || true

CUDA_EVT=$(grep -cE '"(api_id|active_cuda_api)":"(cuLaunchKernel|cuStreamQuery|cuStreamSynchronize|cuMemcpyDtoH|cuMemcpyHtoD)' \
           evidence/overhead_gadget_trace.log 2>/dev/null | tr -d '\n ' || true)
[[ -z "$CUDA_EVT" ]] && CUDA_EVT=0
echo "CUDA events captured during gadget phase: $CUDA_EVT" \
     >> evidence/overhead_preflight.txt

python3 bench/overhead_stats.py \
        evidence/overhead_baseline_hp.jsonl \
        evidence/overhead_withgadget_hp.jsonl \
        "$CUDA_EVT" \
    > "$OUT"
cat "$OUT"
