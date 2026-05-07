#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Inspektor Gadget authors
"""migration_scanner — userspace operator.

Reads JSONL events from the gadget's `ig run` output (one event per line),
loads a policy YAML, and emits a categorised compatibility report.

Generic across all immutable target OSes — every target-OS-specific string
lives in policies/*.yaml, NEVER in this file. Add a fifth target by
dropping a YAML alongside the four shipped built-ins; no code change.
"""

import argparse
import json
import os
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("[migration_scanner] PyYAML required: pip install pyyaml", file=sys.stderr)
    sys.exit(2)

BUILTIN_NAMES = ("acl", "talos", "bottlerocket", "flatcar")

CATEGORY_NAMES = {
    1: "fs_write", 2: "socket", 3: "kmod", 4: "exec",
    5: "capability", 6: "selinux", 7: "fs_mmap",
    8: "fs_link", 9: "fs_symlink",
}
SCOPE_NAMES = {0: "host", 1: "container_hostpath", 2: "container_internal"}


def load_policy(spec: str) -> dict:
    if spec.startswith("builtin:"):
        name = spec.split(":", 1)[1]
        if name not in BUILTIN_NAMES:
            raise ValueError(f"unknown builtin '{name}'; valid: {BUILTIN_NAMES}")
        path = Path(__file__).parent / "policies" / f"{name}.yaml"
    else:
        path = Path(spec)
    with open(path) as f:
        return yaml.safe_load(f)


def has_prefix(path: str, prefixes) -> bool:
    return any(path == p or path.startswith(p.rstrip("/") + "/") for p in (prefixes or []))


def classify(event: dict, policy: dict) -> dict:
    """Return {severity, rule_id, message, recommendation} or None for COMPATIBLE."""
    spec = policy["spec"]
    fs   = spec.get("filesystem", {})
    rt   = spec.get("container_runtime", {})
    km   = spec.get("kernel_modules", {})
    log  = spec.get("logging", {})
    caps = spec.get("capabilities", {})
    bins = spec.get("binaries", {})

    cat = CATEGORY_NAMES.get(event.get("category"), "?")
    path = event.get("path", "")
    scope = SCOPE_NAMES.get(event.get("scope"), "?")
    if scope == "container_internal":
        return None  # BPF drops these; defense-in-depth in userspace too

    # FS_WRITE / MMAP / LINK / SYMLINK on read-only path → BLOCKER
    if cat in ("fs_write", "fs_mmap", "fs_link", "fs_symlink"):
        ro = fs.get("read_only_paths", [])
        wp = fs.get("writable_paths", [])
        if has_prefix(path, ro) and not has_prefix(path, wp):
            recco = "Move state under: " + ", ".join(wp[:4]) if wp else "Use ephemeral overlay"
            return {
                "severity": "BLOCKER",
                "rule_id": f"FS-{cat.upper()}-RO-PATH",
                "message": f"Host {cat} on read-only target path: {path}",
                "recommendation": recco,
            }

    # SOCKET (AF_UNIX connect) → check runtime/logging blocked sockets
    if cat == "socket":
        blocked_sock = rt.get("socket_paths", {}).get("blocked", [])
        if path in blocked_sock or has_prefix(path, blocked_sock):
            return {
                "severity": "BLOCKER",
                "rule_id": "RT-SOCKET-MISSING",
                "message": f"Connect to runtime socket not present on target: {path}",
                "recommendation": f"Use one of: {', '.join(rt.get('socket_paths', {}).get('allowed', []))}",
            }
        if path in log.get("blocked_paths", []):
            return {
                "severity": "WARNING",
                "rule_id": "LOG-LEGACY-SYSLOG",
                "message": f"Legacy syslog socket: {path}",
                "recommendation": f"Use: {', '.join(log.get('supported', ['journald','stdout']))}",
            }

    # KMOD
    if cat == "kmod":
        modname = event.get("arg", "").split(".")[0]
        avail = km.get("available", [])
        unavail = km.get("unavailable", [])
        if modname in unavail:
            return {"severity": "BLOCKER", "rule_id": "KMOD-UNAVAILABLE",
                    "message": f"Kernel module unavailable on target: {modname}",
                    "recommendation": "Remove module load or move to userspace impl"}
        if modname not in avail:
            return {"severity": "WARNING", "rule_id": "KMOD-UNKNOWN",
                    "message": f"Kernel module not in target's known set: {modname}",
                    "recommendation": "Verify against target's kernel module list"}
        return None  # available → compatible

    # EXEC
    if cat == "exec":
        unavail_b = bins.get("unavailable", [])
        avail_b   = bins.get("available", [])
        if path in unavail_b:
            return {"severity": "BLOCKER", "rule_id": "EXEC-UNAVAILABLE",
                    "message": f"Binary not present on target: {path}",
                    "recommendation": "Replace with available equivalent or containerize"}
        if avail_b and path not in avail_b:
            return {"severity": "WARNING", "rule_id": "EXEC-UNKNOWN",
                    "message": f"Binary not in target's manifest: {path}",
                    "recommendation": "Verify availability or containerize"}

    # CAPABILITY
    if cat == "capability":
        cap_id = event.get("cap")
        # Linux capability names indexed by ID (subset)
        cap_names = ["CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_DAC_READ_SEARCH","CAP_FOWNER",
                     "CAP_FSETID","CAP_KILL","CAP_SETGID","CAP_SETUID","CAP_SETPCAP",
                     "CAP_LINUX_IMMUTABLE","CAP_NET_BIND_SERVICE","CAP_NET_BROADCAST",
                     "CAP_NET_ADMIN","CAP_NET_RAW","CAP_IPC_LOCK","CAP_IPC_OWNER",
                     "CAP_SYS_MODULE","CAP_SYS_RAWIO","CAP_SYS_CHROOT","CAP_SYS_PTRACE",
                     "CAP_SYS_PACCT","CAP_SYS_ADMIN","CAP_SYS_BOOT","CAP_SYS_NICE",
                     "CAP_SYS_RESOURCE","CAP_SYS_TIME","CAP_SYS_TTY_CONFIG","CAP_MKNOD",
                     "CAP_LEASE","CAP_AUDIT_WRITE","CAP_AUDIT_CONTROL","CAP_SETFCAP",
                     "CAP_MAC_OVERRIDE","CAP_MAC_ADMIN","CAP_SYSLOG","CAP_WAKE_ALARM",
                     "CAP_BLOCK_SUSPEND","CAP_AUDIT_READ","CAP_PERFMON","CAP_BPF"]
        cap_str = cap_names[cap_id] if 0 <= cap_id < len(cap_names) else f"CAP_{cap_id}"
        if cap_str in caps.get("blocked", []):
            return {"severity": "BLOCKER", "rule_id": "CAP-BLOCKED",
                    "message": f"Host process used capability blocked on target: {cap_str}",
                    "recommendation": "Remove capability requirement or run unprivileged"}

    return None  # compatible


def report(events: list, policy: dict, fmt: str) -> str:
    blockers, warnings, compatible = [], [], []
    for e in events:
        d = classify(e, policy)
        if not d:
            compatible.append(e); continue
        sev = d["severity"]
        item = (e, d)
        if sev == "BLOCKER":   blockers.append(item)
        elif sev == "WARNING": warnings.append(item)
        else:                  compatible.append(e)

    if fmt == "json":
        out = {"blockers": [{"event": e, "decision": d} for e, d in blockers],
               "warnings": [{"event": e, "decision": d} for e, d in warnings],
               "compatible_count": len(compatible),
               "verdict": "READY" if not blockers else "NOT_READY"}
        return json.dumps(out, indent=2)

    if fmt == "text":
        lines = []
        for e, d in blockers + warnings:
            lines.append(f"{d['severity']:8s} {d['rule_id']:24s} pid={e.get('pid')} comm={e.get('comm','?')[:16]:16s} {e.get('path','')}")
        return "\n".join(lines) if lines else "(no findings)"

    # report
    name = policy["metadata"]["name"]
    out = []
    out.append(f"╔══════════════════════════════════════════════════════════════════╗")
    out.append(f"║  Migration Scanner — Compatibility Report                         ║")
    out.append(f"║  Target: {name:55s}║")
    out.append(f"╚══════════════════════════════════════════════════════════════════╝")
    out.append(f"")
    out.append(f"BLOCKERS  ({len(blockers)})")
    for e, d in blockers:
        out.append(f"  ✗ [{d['rule_id']}] {d['message']}")
        out.append(f"      → {d['recommendation']}")
    out.append(f"")
    out.append(f"WARNINGS  ({len(warnings)})")
    for e, d in warnings:
        out.append(f"  ⚠ [{d['rule_id']}] {d['message']}")
    out.append(f"")
    out.append(f"COMPATIBLE events: {len(compatible)}")
    out.append(f"")
    out.append(f"VERDICT: {'READY' if not blockers else 'NOT READY'}")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description="migration_scanner operator")
    ap.add_argument("--policy", default="builtin:talos")
    ap.add_argument("--input", default="-", help="JSONL events file or '-' for stdin")
    ap.add_argument("--output", choices=["text", "json", "report"], default="report")
    args = ap.parse_args()

    policy = load_policy(args.policy)

    events = []
    src = sys.stdin if args.input == "-" else open(args.input)
    for line in src:
        line = line.strip()
        if not line: continue
        try: events.append(json.loads(line))
        except: pass

    print(report(events, policy, args.output))


if __name__ == "__main__":
    main()
