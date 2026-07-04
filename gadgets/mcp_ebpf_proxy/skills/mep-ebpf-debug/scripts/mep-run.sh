#!/usr/bin/env bash
# mep-run: wrapper around `ig run mcp_ebpf_proxy:mep`. Adds verify-image, a
# default timeout, JSON output, and pipes through the summarizer.
# Usage: mep-run.sh <capability> [--pid N] [--timeout S] [gadget flags...]
set -u
IMG="${MEP_IMAGE:-mcp_ebpf_proxy:mep}"
CAP="${1:?usage: mep-run.sh <capability> [params...]}"; shift || true
HAS_TO=0; for a in "$@"; do case "$a" in --timeout*) HAS_TO=1;; esac; done
TO=(); [ "$HAS_TO" = 0 ] && TO=(--timeout=6)
HERE="$(cd "$(dirname "$0")" && pwd)"
sudo ig run "$IMG" --verify-image=false --capability="$CAP" "${TO[@]}" "$@" -o json 2>/dev/null \
  | python3 "$HERE/mep-summarize.py"
