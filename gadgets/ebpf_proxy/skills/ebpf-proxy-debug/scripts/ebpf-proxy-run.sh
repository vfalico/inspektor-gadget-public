#!/usr/bin/env bash
# ebpf-proxy-run: wrapper around `ig run ebpf_proxy:latest`. Adds verify-image, a
# default timeout, JSON output, and pipes through the summarizer.
# Usage: ebpf-proxy-run.sh <capability> [--pid N] [--timeout S] [gadget flags...]
set -u
IMG="${EBPF_PROXY_IMAGE:-ebpf_proxy:latest}"
CAP="${1:?usage: ebpf-proxy-run.sh <capability> [params...]}"; shift || true
HAS_TO=0; for a in "$@"; do case "$a" in --timeout*) HAS_TO=1;; esac; done
TO=(); [ "$HAS_TO" = 0 ] && TO=(--timeout=6)
HERE="$(cd "$(dirname "$0")" && pwd)"
sudo ig run "$IMG" --verify-image=false --capability="$CAP" "${TO[@]}" "$@" -o json 2>/dev/null \
  | python3 "$HERE/ebpf-proxy-summarize.py"
