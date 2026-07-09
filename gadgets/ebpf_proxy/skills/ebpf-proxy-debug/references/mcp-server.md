# Driving eBPF Proxy over MCP (agent / tool-call interface)

eBPF Proxy can be driven two ways: the `ig` CLI (everything else in this skill), or as an
**MCP tool** an agent calls directly. The capability model is identical — same
`capability` selector, same params, same datasources/fields. MCP just changes the
transport: instead of a shell command you emit a tool call, and instead of parsing
stdout you receive structured rows.

## When to use MCP vs CLI
- **CLI** — you're at a shell, doing interactive RCA, or scripting `ebpf-proxy-run.sh`.
- **MCP** — an MCP-capable assistant is doing the RCA and should pick the capability,
  read the rows, and iterate autonomously. The agent never rebuilds or restarts
  anything; eBPF Proxy stays a single read-only gadget.

## The invariant contract (both transports)
1. **One capability per call.** The WASM control plane enables only that
   capability's programs and filter maps. Don't expect two capabilities' columns in
   one call — make two calls.
2. **`ebpf_proxy_coverage` first.** Every call returns exactly one coverage record
   (`capability`, `attached_targets`, `attached_count`, `pid_filter`, `note`) plus
   the event rows. Read coverage before concluding "nothing happened":
   `attached_count>0` + zero events = attached-but-idle (widen the window), NOT a
   failure.
3. **Scope in-kernel.** Pass `pid` and a short `timeout`; use the op-class selectors
   (`fs_op`, `cuda_op`) and the aggregating capabilities (`per_key_rollup`) to stay
   under the output budget. High-rate capabilities (`runq_lat`, unfiltered `attach`,
   `trace_syscall` with no syscall) flood — always narrow first.
4. **Identity is inline.** Socket-bearing rows already carry the 4-tuple +
   `sk_state` — the agent should read those fields rather than issuing a second
   "which connection" call (see connection-identity.md).

## Capability → param cheatsheet for tool calls
Pass these as the tool's structured arguments (names match the CLI flags):

| capability | required args | useful optional args |
|---|---|---|
| `attach` | `function` | `mode`, `pid`, `timeout` |
| `attach_uprobe` | `target` (`lib:sym`) | `mode`, `pid` (attach scope), `timeout` |
| `trace_syscall` | `syscall`, `pid` | `timeout` |
| `fs_trace` | — | `fs_op` (`fault`/`filp_open`/`close`), `pid`, `timeout` |
| `net_trace` | — | `pid`, `timeout` |
| `sock_state` | — | `pid`, `timeout` |
| `sock_snapshot` | — | `pid`, `timeout` |
| `sockpair_correlate` | — | `pid`, `timeout` |
| `epoll_timer` | — | `pid`, `timeout` |
| `absence_assert` | `host`, `absence_period_ns` | `pid`, `timeout` |
| `per_key_rollup` | — | `pid`, `timeout` |
| `heap_profile` / `lock_trace` / `mm_trace` / `irq_trace` / `block_io` / `runq_lat` | — | `pid`, `timeout` |
| `list_attachable` | — | `filter`, `max`, `type` |
| `cuda_*` | — | see ebpf-proxy-gpu-debug |

## Agent RCA loop over MCP (recommended)
1. Read the symptom → pick ONE capability from SKILL.md §1.
2. Call it scoped (`pid` + short `timeout`).
3. Inspect `ebpf_proxy_coverage`: attached but idle → re-call with a wider `timeout`.
4. Read the decisive field for that capability (SKILL.md §1 "reference" column).
5. If the evidence points at another layer, pivot capability (e.g. `sock_snapshot`
   found a wedged socket → `sock_state` for how it got wedged).
6. Stop when a single field proves the fault (e.g. `verdict=FAIL`,
   `newstate=CLOSE` with no ESTABLISHED, `sk_null=1`, `retrans_count` spike).

## Gotchas specific to MCP driving
- The agent must still treat the gadget as **one call = one capability**; a prompt
  that asks for "sockets and syscalls" needs two tool calls.
- `timeout` is the capture window — an MCP call blocks for roughly that long. Keep it
  short (1–3 s) for a first look; a 30 s window on a high-rate capability returns a
  truncated flood, not more insight.
- Errors surface in `ebpf_proxy_coverage.note` / a non-zero attach — surface them to the
  agent instead of silently reporting "no data".
- Local/unsigned image still needs the equivalent of `--verify-image=false`; if the
  MCP server was started against a signed registry image this is already handled.
