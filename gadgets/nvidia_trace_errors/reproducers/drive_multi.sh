#!/bin/bash
# Multi-container cross-contamination test. pod-A runs a benign CUDA loop;
# pod-B runs the XID 31 reproducer. Confirms the gadget attributes the XID
# to pod-B (not pod-A) even though both share the single A100.
set -eu
OUT=$1
IMG=ghcr.io/inspektor-gadget/gadget/nvidia_trace_errors:xid-workload-correlation

docker rm -f nvte-multi-a nvte-multi-b >/dev/null 2>&1 || true
echo "[pre] nvidia-smi" >"$OUT.stderr"
nvidia-smi --query-compute-apps=pid,name,used_memory --format=csv >>"$OUT.stderr"

sudo -n ig run "$IMG" --verify-image=false -r docker --collect-ustack \
	-o jsonpretty --timeout=60 >"$OUT" 2>>"$OUT.stderr" &
IG=$!
sleep 4

# Pod-A: benign loop, starts first, keeps libcuda active.
docker run -d --rm --name nvte-multi-a --gpus=all nvte-repro:latest /usr/local/bin/benign >/dev/null

sleep 6   # Give pod-A time to rack up many cuStreamQuery calls.

# Pod-B: fires XID 31.
docker run --rm --name nvte-multi-b --gpus=all nvte-repro:latest /usr/local/bin/xid31 >/dev/null 2>&1 || true

wait $IG || true
docker rm -f nvte-multi-a nvte-multi-b >/dev/null 2>&1 || true
echo "[post] nvidia-smi" >>"$OUT.stderr"
nvidia-smi --query-compute-apps=pid,name,used_memory --format=csv >>"$OUT.stderr"
echo "[post] dmesg tail" >>"$OUT.stderr"
sudo -n dmesg -T | tail -60 | grep -iE "xid|nvrm" >>"$OUT.stderr" || true
