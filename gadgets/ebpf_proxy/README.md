# ebpf_proxy — multi-capability read-only kernel + GPU observation gadget

`ebpf_proxy` is a single [Inspektor Gadget](https://inspektor-gadget.io) image that
exposes many read-only kernel and GPU **observation capabilities** behind one gadget.
You select ONE `capability`; a small WASM control plane enables only that capability's
eBPF programs and populates the in-kernel filter maps, and you read a structured
datasource. **Every capability is read-only — it observes, it never modifies the
target process or the kernel.**

The same gadget is usable three ways: directly from a shell (**CLI**), through an LLM
**skill** (`ebpf-proxy-debug`, which maps a symptom to the right capability and runs
the CLI for you), or through the **MCP server** (`ig-mcp-server`, which exposes the
gadget as the MCP tool `gadget_ebpf_proxy`). All three drive the same capabilities.

---

## Capabilities

Select exactly one with `--capability=<name>`.

| capability | what it observes |
|---|---|
| `attach` | kprobe/kretprobe on ANY kernel function chosen at run time |
| `attach_uprobe` | uprobe/uretprobe on ANY userspace `<lib-or-path>:<symbol>` |
| `trace_syscall` | raw_syscalls sys_enter/sys_exit for a syscall name + pid |
| `list_attachable` | enumerate kprobe-able kernel symbols (via iter/ksym) |
| `fs_trace` | vfs_read/write/open, failing opens (do_filp_open, ENOENT) and fd-leak balance via filp_close |
| `net_trace` | TCP connect / retransmit / sendmsg with decoded daddr/dport |
| `sock_state` | socket lifecycle: connection refused vs reset vs peer-FIN (`reset_dir`, `sk_null`) |
| `heap_profile` | libc malloc/calloc/realloc/free churn + leak, plus kernel brk/anon-mmap growth |
| `lock_trace` | userspace pthread mutex/cond wait — blocked time + lock address |
| `mm_trace` | page-fault + direct-reclaim with duration (memory pressure) |
| `irq_trace` | softirq service time per vector |
| `block_io` | per-request block-device latency (dev, sector, is_write) |
| `runq_lat` | scheduler run-queue latency per task (CPU starvation) |
| `cuda_memtrace` | CUDA driver + runtime alloc/free; size + ptr per event |
| `cuda_memsnapshot` | standing per-PID GPU memory residency via NVML |
| `cuda_smutil` | standing per-PID GPU compute (SM) utilization via NVML |
| `cuda_profile` | GPU launch/sync/memcpy + grid/block dims, stream, size |

A machine-readable version of this list ships inside the gadget as
`capability_catalog.json`.

---

## Requirements & permissions

- A Linux host with a recent kernel and BTF available (`/sys/kernel/btf/vmlinux`).
- `ig` (the Inspektor Gadget CLI) with permission to load eBPF programs — in
  practice this means running as **root** (or with `CAP_BPF` + `CAP_PERFMON` +
  `CAP_SYS_ADMIN`, depending on the capability). The examples below use `sudo`.
- The `cuda_*` capabilities additionally require an NVIDIA GPU with a working
  driver / NVML on the host.
- `--verify-image=false` is required when running a locally built (unsigned) image.

---

## CLI usage

```
sudo ig run ebpf_proxy:latest --verify-image=false \
    --capability=<CAP> [params] --timeout=<seconds> -o json
```

- Prefer `-o json`; process identity is nested under `proc.*` (`proc.comm`,
  `proc.pid`). `-o columns` flattens to a per-datasource header row.
- Always pass `--pid` and a short `--timeout` first, then widen only if the window
  was idle.

### Example — "the app can't find its config" (ENOENT storm)

```
sudo ig run ebpf_proxy:latest --verify-image=false \
    --capability=fs_trace --fs_op=fault --pid=<PID> --timeout=10 -o json
```

Emits the failing-open events (`do_filp_open` returning `-2` ENOENT) with the
requested path in `fname` — you see exactly which file the process is missing.
Expected fields include `proc.comm`, `proc.pid`, `fs_op`, `fname`, `ret`.

### Example — "connection refused vs reset"

```
sudo ig run ebpf_proxy:latest --verify-image=false \
    --capability=sock_state --pid=<PID> --timeout=10 -o json
```

`sk_null=1` on an RST received in `SYN_SENT` is the classic ECONNREFUSED shape;
`reset_dir` distinguishes an inbound vs outbound reset. Expected fields include
`proc.comm`, `saddr`/`daddr`, `sport`/`dport`, `sk_state`, `reset_dir`, `sk_null`.

### Example — "memory keeps growing"

```
sudo ig run ebpf_proxy:latest --verify-image=false \
    --capability=heap_profile --pid=<PID> --timeout=15 -o json
```

Tracks libc allocation churn and kernel `brk`/anonymous-mmap growth so a leak in
the host process is visible. Expected fields include `proc.pid`, `op`, `size`, `ptr`.

---

## Skill usage (LLM)

The `ebpf-proxy-debug` skill (under `gadgets/ebpf_proxy/skills/`) routes from a
plain-language **symptom** to the correct capability and runs the CLI via
`scripts/ebpf-proxy-run.sh`. Its symptom→capability decision map:

| Symptom / user words | capability + key params |
|---|---|
| "can't find config", ENOENT storm, failing opens | `fs_trace --fs_op=fault --pid=<PID>` |
| suspected fd leak (opens ≫ closes) | `fs_trace --pid=<PID>` (balance vs `fs_op=close`) |
| malloc / memory keeps growing | `heap_profile --pid=<PID>` |
| hanging on a mutex / cond wait | `lock_trace --pid=<PID>` |
| TCP retransmits, slow connect | `net_trace --pid=<PID>` |
| connection refused vs reset vs peer-FIN | `sock_state --pid=<PID>` |

Reference docs live under `skills/ebpf-proxy-debug/references/`
(`capabilities.md`, `socket-lifecycle.md`, `install.md`, `mcp-server.md`, and more).

---

## MCP usage (LLM)

`ig-mcp-server` exposes this gadget as the MCP tool **`gadget_ebpf_proxy`**. An
MCP client calls `tools/list`, then `tools/call` with `name="gadget_ebpf_proxy"`
and the capability + parameters as arguments — no shell required. When calling the
WASM operator directly, pass the capability under the full operator key
`operator.oci.wasm.capability=<CAP>`.

---

## Safety

All capabilities are strictly read-only kernel/GPU **observers**: they attach
kprobes/uprobes/tracepoints and read counters, they never write to the traced
process or modify kernel state. Loading eBPF still requires elevated privileges
(see *Requirements & permissions*), so run it only on hosts where you are
authorized to trace, and prefer a narrow `--pid` + short `--timeout`.
