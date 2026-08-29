---
name: ebpf-proxy-debug
description: >-
  Diagnose a running Linux application with the read-only eBPF Proxy gadget via
  Inspektor Gadget CLI or MCP. Covers bounded capability selection, target and
  coverage validation, syscalls, I/O, locks, memory, scheduling, networking,
  GPU activity, and kprobe/uprobe attachment. Do not use for static-only analysis.
license: Apache-2.0
metadata:
  version: "2.0.0"
  homepage: https://github.com/inspektor-gadget/inspektor-gadget/tree/main/gadgets/ebpf_proxy
---

# eBPF Proxy — Multi-capability eBPF debug (CLI or MCP, no rebuild)

eBPF Proxy (`ebpf_proxy`) is ONE read-only Inspektor Gadget gadget that retargets at
runtime. You pick a `capability`; eBPF Proxy's WASM control plane enables only that
capability's eBPF programs and populates in-kernel filter maps. Run it directly
with `ig`, or drive it from an agent over MCP (see `references/mcp-server.md`).
Every capability is read-only — it observes, it never modifies the target.

## 0. Golden invocation

```bash
sudo ig run ebpf_proxy:latest --verify-image=false \
    --capability=<CAP> [params] --timeout=<seconds> -o json
```

- `--verify-image=false` is required for a locally-built/unsigned image (else `ig`
  fails with `pulling signing information ... 401 unauthorized`).
- Every run also emits ONE `ebpf_proxy_coverage` record — read it FIRST (section 4).
- Prefer `-o json`; process identity is nested under `proc` (`proc.comm`,
  `proc.pid`). `-o columns` flattens to `COMM`/`PID` with a per-datasource header.

If `ig` is missing or the image isn't built, run `scripts/ebpf-proxy-doctor.sh`. Full
install/build recipe: `references/install.md`. MCP driving: `references/mcp-server.md`.

## 1. Symptom → capability decision map (start here)

Every socket-bearing event now also carries the **4-tuple + socket state inline**
(`saddr/daddr/sport/dport/sk_state/sk_family`) — you rarely need a second capability
just to learn "which connection". See `references/connection-identity.md`.

| Symptom / user words | capability + key params | reference |
|---|---|---|
| "can't find config", ENOENT storm, failing opens | `fs_trace --fs_op=fault --pid=<PID>` | capabilities.md |
| suspected fd leak (opens >> closes) | `fs_trace --pid=<PID>` (balance vs `fs_op=close`) | capabilities.md |
| malloc/memory keeps growing, heap churn | `heap_profile --pid=<PID>` | capabilities.md |
| hanging on a mutex / cond wait | `lock_trace --pid=<PID>` | capabilities.md |
| TCP retransmits, slow connect, sendmsg volume | `net_trace --pid=<PID>` | capabilities.md |
| **connection refused vs reset vs peer-FIN** | `sock_state --pid=<PID>` | socket-lifecycle.md |
| **inbound/outbound RST, stale-endpoint RST** | `sock_state` (`reset_dir`, `sk_null`) | socket-lifecycle.md |
| **"what does this socket look like NOW"** | `sock_snapshot` | socket-lifecycle.md |
| **which upstream socket serves this downstream** | `sockpair_correlate` | connection-identity.md |
| **who is the peer pod / far-end identity** | `net_trace` (`dst_endpoint`) + k8s meta | connection-identity.md |
| high latency of syscall X | `trace_syscall --syscall=<name> --pid=<PID>` | capabilities.md |
| **event loop stalled (epoll/timerfd/hrtimer)** | `epoll_timer --pid=<PID>` | event-loop.md |
| **recursion / call never returned** | `attach`/`attach_uprobe` (`call_depth`, `phase`) | event-loop.md |
| **stack-depth blowup / near-overflow** | `attach_uprobe` (`stack_used`, `stack_alarm`) | event-loop.md |
| **a periodic write (keepalive/SSE) stopped** | `absence_assert --host --absence_period_ns=<ns>` | reliability-asserts.md |
| **per-flow counters + inter-event gaps** | `per_key_rollup` (via net_rollup) | reliability-asserts.md |
| **decode a string arg at a uprobe** | `attach_uprobe` (`arg_str`) | event-loop.md |
| **bind a userspace fd to its kernel socket** | `attach_uprobe` fd-arg (`daddr/dport` inline) | connection-identity.md |
| scheduler / run-queue latency | `runq_lat --pid=<PID>` (high rate — scope it) | capabilities.md |
| page faults / direct reclaim / mem pressure | `mm_trace --pid=<PID>` | capabilities.md |
| block device / disk I/O latency | `block_io` | capabilities.md |
| softirq storm | `irq_trace` | capabilities.md |
| RCA a specific KERNEL function | `attach --function=<sym> --mode=kprobe_kretprobe` | capabilities.md |
| RCA a specific USERSPACE lib function | `attach_uprobe --target=<lib>:<sym>` | capabilities.md |
| "what kernel symbols can I attach to?" | `list_attachable --filter=<pfx> --max=<n> --type=t` | capabilities.md |
| GPU VRAM leak / residency / SM utilization | see the `ebpf-proxy-gpu-debug` skill | — |

Full field-by-field catalog: `references/capabilities.md`.
Runnable one-liner per capability with REAL output: `references/verified-runs.md`.

## 2. The debug loop: plan → run → interpret → fix

1. **Plan.** Map symptom → capability above. Get target `PID` (`pgrep -f <name>`).
   Unknown symbol? Run `list_attachable` first. Proxy/mesh? Read
   `references/connection-identity.md` — the inline 4-tuple usually removes a step.
2. **Run.** Use `scripts/ebpf-proxy-run.sh <cap> [--pid N] [params]` (adds
   `--verify-image=false`, a default `--timeout`, `-o json`, summarizer), or the
   golden invocation, or drive over MCP (`references/mcp-server.md`).
3. **Interpret.** `scripts/ebpf-proxy-summarize.py` separates `ebpf_proxy_coverage` from events,
   resolves `proc.*`, and ranks files/ports/return-codes. Read `ebpf_proxy_coverage`
   FIRST (section 4). For socket lifecycle, read state transitions not proc.
4. **Fix.** Translate evidence → fix, re-run the SAME capability to confirm the
   signal is gone. For `absence_assert`, a PASS verdict IS the confirmation.

## 3. In-kernel op-class filters (avoid truncation)

High-rate capabilities flood if unfiltered. Narrow IN-KERNEL before widening:
- `fs_trace --fs_op=fault` → only failing opens (ENOENT/EACCES).
- `fs_trace --fs_op=filp_open|close` → isolate open vs close (fd-leak balance).
- `cuda_profile --cuda_op=copy|h2d|d2h` → only PCIe transfer rows.
- `sock_state` is transition-driven (naturally low-rate); `sock_snapshot` and
  `absence_assert` are point-in-time walks (one pass, not a firehose).
- Always pass `--pid` and a short `--timeout` first; widen only if idle.

## 4. Reading `ebpf_proxy_coverage` (the most important row)

Each run emits one record: `capability`, `attached_targets`, `attached_count`,
`pid_filter`, `note`. Decision rule:
- `attached_count > 0` AND zero events → **attached-but-idle**: probes are on, the
  workload produced nothing in the window. WIDEN `--timeout`/`--pid` — do NOT switch
  capability. (For `sock_snapshot`/`absence_assert`, zero rows can mean no live
  sockets matched — check `--host`/filters.)
- attach error (symbol not found) → for `attach`, run `list_attachable`; enriched
  families use fixed SEC-default targets and won't error on a missing symbol.

## 5. Critical gotchas (see `references/gotchas.md` for all)

- `list_attachable` flags are `--filter` / `--max` / `--type` (NOT `--ksym_filter`).
  Symbols render in `-o columns` (`TYPE NAME MODULE`; TYPE 116 = 't' = function).
- `-o json` nests process identity under `proc.*`.
- Gadget `--pid` filters events. For uprobe-backed capabilities, also pass
  `--operator.oci.wasm.pid=<same PID>` so attachment resolves against that
  process rather than unrelated long-lived host processes. Kernel-only
  capabilities need only gadget `--pid`.
- `attach_uprobe --target` requires the exact raw linker symbol. Resolve Rust/C++
  targets with `nm --no-demangle` (and `-D` for dynamic exports); never copy a
  readable `nm -C` name containing `::` into the attach command.
- `sock_state`/RST rows often fire in softirq/timer context — key on the **4-tuple**,
  not `proc` (it may name an incidentally-running task).
- `absence_assert` needs `--host` and, to record writes, pair it with a `net_trace`
  window; `period=0` emits observational INFO rows only.
- NVML per-PID GPU fields are often 0 inside containers by design — expected.
- `runq_lat`, unfiltered `attach`, and `trace_syscall` (no syscall) are very
  high-rate — always scope.
