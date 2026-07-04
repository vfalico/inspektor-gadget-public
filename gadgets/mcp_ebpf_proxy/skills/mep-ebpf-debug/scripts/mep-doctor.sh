#!/usr/bin/env bash
# mep-doctor: verify prereqs for running MEP via the ig CLI (no MCP server).
set -u
IMG="${MEP_IMAGE:-mcp_ebpf_proxy:mep}"
ok(){ echo "  OK  $*"; }; bad(){ echo " MISS $*"; }
echo "== MEP prereq check =="
[ "$(id -u)" = 0 ] || echo "  note: run MEP with sudo (needs CAP_BPF+CAP_PERFMON or root)"
command -v ig >/dev/null && ok "ig: $(ig version 2>/dev/null | head -1)" || bad "ig not on PATH — see references/install.md"
[ -r /sys/kernel/btf/vmlinux ] && ok "BTF present" || bad "no BTF — CO-RE gadgets need /sys/kernel/btf/vmlinux"
[ -r /proc/kallsyms ] && ok "kallsyms readable" || echo "  note: kallsyms restricted (kptr_restrict) — run as root"
if command -v ig >/dev/null; then
  sudo ig image list 2>/dev/null | grep -q "$IMG" && ok "image $IMG present" || bad "image $IMG not built — see references/install.md"
fi
echo "== smoke: list_attachable (proves end-to-end) =="
sudo timeout 20 ig run "$IMG" --verify-image=false --capability=list_attachable --filter=do_sys_open --max=3 -o columns 2>/dev/null | grep -iE 'do_sys_open' | head -3 || echo "  (no smoke output — check MISS lines)"
