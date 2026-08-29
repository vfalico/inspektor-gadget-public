# eBPF Proxy capability catalog (params + fields) — 20 capabilities

Invocation: `sudo ig run ebpf_proxy:latest --verify-image=false --capability=<CAP> [params] --timeout=<s> -o json`
Common params: `--pid=<N>` (in-kernel event filter), `--timeout=<s>`.
Every run emits one `ebpf_proxy_coverage` record (see gotchas.md #7). Socket-bearing rows
carry the **inline 4-tuple** `saddr/daddr/sport/dport/sk_state/sk_family` — see
`connection-identity.md`.

## CORE (you pick the attach target)
### attach — raw kprobe/kretprobe on a kernel function
- params: `--function=<kernel symbol>`, `--mode=kprobe|kretprobe|kprobe_kretprobe` (default kprobe_kretprobe)
- fields: `func, arg0..arg4, arg_str, retval, phase(enter|ret), phase_raw, call_depth, stack_used, stack_alarm` + inline 4-tuple
- validate the symbol with `list_attachable` first.

### attach_uprobe — uprobe/uretprobe on a userspace symbol
- params: `--target=<lib-or-path>:<symbol>` (e.g. `libc:malloc`, `libssl:SSL_read`), `--mode=uprobe|uretprobe|uprobe_uretprobe` (default `uprobe_uretprobe`)
- `<symbol>` must be the exact raw linker symbol, not a demangled Rust/C++ display name. Discover it without demangling:
  `nm --no-demangle --defined-only <binary-or-library> | grep '<stable fragment>'`.
  For dynamic exports use `nm -D --no-demangle --defined-only`. Copy the complete
  symbol-name column into `--target`; use `nm -C` only to understand candidates,
  never as the source of the attach string.
- auto-pairs enter/return (`call_depth`), decodes a `char*` arg to `arg_str`, resolves an fd arg to the kernel socket (inline 4-tuple). See event-loop.md, connection-identity.md.
- the WASM operator `pid` scopes ATTACH resolution; gadget `--pid` filters events.

### trace_syscall — raw_syscalls enter/exit for a pid
- params: `--syscall=<name>` (openat, execve, kill, ...), `--pid=<N>`
- fields (`ebpf_proxy_sys`): `syscall(DECODED), syscall_nr_raw, arg0..arg5, retval, duration_ns, phase` + inline 4-tuple

### list_attachable — enumerate kprobe-able kallsyms
- params: `--filter=<prefix>` (key `filter`), `--max=<n>` (key `max`), `--type=<char>` (key `type`, e.g. `t`)
- renders in `-o columns` as `TYPE NAME MODULE` (TYPE 116 = 't' = function). See gotchas #2/#3.

### cuda_memtrace / cuda_memsnapshot / cuda_smutil / cuda_profile — GPU (see ebpf-proxy-gpu-debug skill)

## ENRICHED swiss-army families (decoded per-subsystem columns; fixed SEC-default targets)
### fs_trace — VFS read/write/open (datasource `ebpf_proxy_fs`)
- params: `--fs_op=fault|filp_open|close`, `--pid=<N>`
- fields: `fname, retval(errno as -N), fs_op, fs_op_raw, count` + inline 4-tuple
- `fs_op=fault` = only failing opens (ENOENT/EACCES); best for "can't find config".

### net_trace — TCP connect/retransmit/sendmsg (datasource `ebpf_proxy_net`)
- fields: `daddr, saddr, dport, sport, bytes, retval, retrans_out, tcp_state, connect_latency_ns, net_op_raw, dst_endpoint(peer, k8s-resolved)`

### heap_profile — libc malloc/free churn+leak
- Uprobe-backed: use both `--pid=<PID>` and
  `--operator.oci.wasm.pid=<PID>` with the same verified identity.
- attaches malloc/calloc/realloc/free/brk/mmap (+rets); fields `size, ptr, heap_op`.

### lock_trace — userspace mutex/cond wait
### mm_trace — page-fault + direct reclaim
### irq_trace — softirq service time (`vec, duration_ns`)
### block_io — per-request block device latency
### runq_lat — scheduler run-queue latency (`cpu, runq_ns`) — VERY HIGH RATE, always scope

## Socket-state, correlation, event-loop & reliability capabilities (detail in the domain references)
### sock_state — TCP state-machine + RST direction (datasource `ebpf_proxy_sockstate`) → socket-lifecycle.md
- fields: `ss_op(transition|reset_rx|reset_tx), ss_op_raw, oldstate, newstate, saddr/daddr/sport/dport, family, reset_dir(0/1/2), sk_null`
- decisive: `SYN_SENT→CLOSE` no ESTABLISHED = refused; `ESTABLISHED→CLOSE_WAIT` = peer FIN; `sk_null=1` = stale-endpoint RST.

### sock_snapshot — point-in-time TCP iterator (datasource `ebpf_proxy_socksnap`) → socket-lifecycle.md
- fields: `saddr/daddr/sport/dport, family, state, netns_id, sock_kind, srtt_us, rto, retransmits, snd_cwnd, sndq_bytes, unacked_bytes, rcvq_bytes, last_snd_ts`
- decisive: high `unacked_bytes`+`retransmits` = peer not ACKing; high `rcvq_bytes` = app not reading.

### sockpair_correlate — downstream↔upstream socket link (datasource `ebpf_proxy_sockpair`) → connection-identity.md
- fields: `down_{saddr,daddr,sport,dport}, up_{saddr,daddr,sport,dport}, down_state, up_state, up_retval, accept_to_connect_ns, proc`
- decisive: one row = one proxied flow; `up_retval<0` = backend refused; big `accept_to_connect_ns` = proxy routing latency.

### epoll_timer — event-loop causal chain (datasource `ebpf_proxy_timer`) → event-loop.md
- fields: `kind_raw, fd, nready, ev_mask, op, expires_ns, timer_ptr, proc`
- decisive: `epoll_wait nready=0` spin = spurious wakeups; arm without re-arm = heartbeat timer died.

### absence_assert — proof a periodic write stopped (datasource `ebpf_proxy_absence`) → reliability-asserts.md
- params: `--host`, `--absence_period_ns=<ns>` (0 = observational INFO only)
- fields: `verdict, saddr/daddr/sport/dport, state, last_write_gap_ns, expected_period_ns, observed_max_gap_ns, write_count, closing_evts`
- decisive: `verdict=FAIL` + `closing_evts=0` = silent app stall; `+closing_evts>0` = flow closed.

### per_key_rollup — per-flow counters & gap distribution (datasource `net_rollup`) → reliability-asserts.md
- fields: `saddr/daddr/sport/dport, count, bytes_sum, gap_min_ns, gap_max_ns, gap_sum_ns, retrans_count, rst_count, closing_evts, last_state, first_ts_raw, last_ts_raw, pid, comm`
- decisive: anti-truncation — one row/flow; rank by `retrans_count`/`rst_count`; `gap_max_ns` spike = periodic stall.

### uprobe_argdecode — symbolized string arg (`arg_str` on `ebpf_proxy`) → event-loop.md
### stack_watermark — near-overflow one-shot alarm (`stack_used`,`stack_alarm` on `ebpf_proxy`) → event-loop.md
### call_depth pairing — recursion/never-returned (`call_depth`,`phase` on `ebpf_proxy`) → event-loop.md
### kern_user_correlate — userspace fd → kernel socket (inline 4-tuple on uprobe rows) → connection-identity.md
### inline per_conn_identity — 4-tuple on every socket-bearing event (all datasources) → connection-identity.md

## Cross-cutting params
- `--pid=<N>` — in-kernel `filter_pid` map; the single most useful scoping knob.
- `--timeout=<s>` — capture window; short first, widen if attached-but-idle.
- `--function, --syscall, --target, --mode, --fs_op, --cuda_op` — per-capability selectors.
- `--host, --absence_period_ns` — absence_assert scope + expected cadence.
- `--filter/--max/--type` — list_attachable only (kallsyms prefix / cap / type char).
