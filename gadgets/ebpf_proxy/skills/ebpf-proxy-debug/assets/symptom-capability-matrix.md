# eBPF Proxy symptom → capability matrix (embeddable)

| Symptom | Capability | Key params | Decisive field |
|---|---|---|---|
| Can't find config / ENOENT storm | fs_trace | `--fs_op=fault --pid=N` | `retval=-2`, `fname` |
| fd leak (opens >> closes) | fs_trace | `--pid=N` (open vs `fs_op=close`) | open/close balance |
| Memory keeps growing / heap churn | heap_profile | `--pid=N` | `heap_op`, `size` |
| Hanging on a mutex/cond | lock_trace | `--pid=N` | wait duration |
| TCP retransmits / slow connect | net_trace | `--pid=N` | `retrans_out`, `connect_latency_ns`, `tcp_state` |
| Connection refused vs reset vs peer-FIN | sock_state | `--pid=N` | `oldstate→newstate` (SYN_SENT→CLOSE=refused) |
| Inbound vs outbound RST | sock_state | `--pid=N` | `ss_op`, `reset_dir` (1=rx,2=tx) |
| Stale-endpoint RST (no socket) | sock_state | `--pid=N` | `sk_null=1` + parsed 4-tuple |
| "What does this socket look like NOW" | sock_snapshot | `--pid=N` | `state`, `srtt_us`, `unacked_bytes`, `rcvq_bytes` |
| Stuck send (peer not ACKing) | sock_snapshot | `--pid=N` | `unacked_bytes`↑ `retransmits`↑ `rto`↑ |
| App not draining recv | sock_snapshot | `--pid=N` | `rcvq_bytes`↑ |
| Which upstream serves this downstream | sockpair_correlate | `--pid=N` | `down_*`↔`up_*`, `up_retval`, `accept_to_connect_ns` |
| Who is the peer pod / far-end | net_trace | `--pid=N` | `dst_endpoint` (k8s-resolved) |
| Bind userspace fd → kernel socket | attach_uprobe | `--target=bin:sym --pid=N` | inline `daddr/dport/sk_state` on uprobe row |
| High syscall latency | trace_syscall | `--syscall=X --pid=N` | `duration_ns`, `retval` |
| Event loop stalled (epoll/timerfd) | epoll_timer | `--pid=N` | `nready=0` spin, `ev_mask` HUP/ERR |
| Heartbeat timer never re-armed | epoll_timer | `--pid=N` | arm→expire→(no arm), `timer_ptr` |
| Recursion / call never returned | attach_uprobe | `--target=bin:sym --pid=N` | `call_depth`↑ with unpaired `phase=enter` |
| Stack-depth blowup / near-overflow | attach_uprobe | `--target=bin:sym` (arm watermark) | `stack_alarm=1`, `stack_used` |
| Decode a string arg at a uprobe | attach_uprobe | `--target=bin:sym` | `arg_str` |
| A periodic write (keepalive/SSE) stopped | absence_assert | `--host --absence_period_ns=N` | `verdict`, `observed_max_gap_ns`, `closing_evts` |
| Per-flow counters + gap distribution | per_key_rollup | `--pid=N` | `count`, `bytes_sum`, `gap_max_ns`, `retrans_count`, `rst_count` |
| Scheduler / run-queue latency | runq_lat | `--pid=N --timeout=3` | `runq_ns` |
| Page faults / reclaim pressure | mm_trace | `--pid=N` | fault/reclaim counts |
| Block / disk I/O latency | block_io | (system-wide) | request latency |
| Softirq storm | irq_trace | (system-wide) | `vec`, `duration_ns` |
| RCA a kernel function | attach | `--function=SYM --mode=kprobe_kretprobe --pid=N` | `retval`, `phase`, `call_depth` |
| RCA a userspace lib function | attach_uprobe | `--target=lib:sym --pid=N` | `retval`, `phase`, `arg_str` |
| Which kernel symbols exist? | list_attachable | `--filter=PFX --max=N --type=t` | `NAME` |
| GPU VRAM leak / residency / SM% | (ebpf-proxy-gpu-debug) | cuda_memtrace/memsnapshot/smutil | `used_gpu_mem`, `sm_util` |

Always: read `ebpf_proxy_coverage` first; scope with `--pid` + short `--timeout`; every
socket-bearing row already carries the inline 4-tuple (`saddr/daddr/sport/dport/
sk_state`) so you seldom need a second capability just to identify the connection.
