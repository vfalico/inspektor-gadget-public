#!/bin/bash
# Reproducer runner for XID correlation tests. Expects $1 = xid13|xid31|xid43.
# Pre-run safety: nvidia-smi must be clean except for the known vLLM/baseline
# process. Compiles the .cu inside the cuda-devel image and runs it as a
# short-lived container with --gpus=all so libcuda is the real driver.
set -eu
xid=$1
src=/home/azdev/ig-upstream/gadgets/nvidia_trace_errors/reproducers/${xid}.cu
[ -f "$src" ] || { echo "missing $src"; exit 1; }
name="repro-${xid}-$$"
img=nvidia/cuda:12.3.2-devel-ubuntu22.04

echo "[pre] nvidia-smi:"
nvidia-smi --query-compute-apps=pid,name,used_memory --format=csv

docker rm -f "$name" 2>/dev/null || true
docker run -d --rm --name "$name" --gpus=all \
	-v "$(dirname $src)":/src:ro \
	"$img" bash -c "
		nvcc -arch=sm_80 /src/${xid}.cu -o /tmp/r && exec /tmp/r
	" >/dev/null

# Wait for the reproducer to finish (or hit the nvcc compile step).
for i in $(seq 1 30); do
	sleep 1
	if ! docker ps --format '{{.Names}}' | grep -q "^${name}$"; then
		break
	fi
done
echo "[post] nvidia-smi:"
nvidia-smi --query-compute-apps=pid,name,used_memory --format=csv
echo "[post] dmesg-tail:"
sudo -n dmesg -T | tail -20 | grep -iE "xid|nvrm" || true
