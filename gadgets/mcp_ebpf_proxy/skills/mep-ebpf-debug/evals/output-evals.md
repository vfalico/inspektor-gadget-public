# Output evals for mep-ebpf-debug (correct capability + params selection)
# Scenario -> expected capability & decisive params. Verified shapes match
# references/verified-runs.md captured on slavanestedvm.

| # | Scenario | Expected capability | Expected key params | Decisive field |
|---|---|---|---|---|
| 1 | "PID 55577 can't find /etc/myapp/missing.conf" | fs_trace | `--fs_op=fault --pid=55577` | `retval=-2`, `fname` |
| 2 | "does PID X leak fds?" | fs_trace | `--pid=X` compare open vs `fs_op=close` | open/close delta |
| 3 | "PID X memory grows, malloc leak?" | heap_profile | `--pid=X` | `heap_op`,`size` |
| 4 | "threads deadlock on mutex in PID X" | lock_trace | `--pid=X` | wait duration |
| 5 | "TCP resets/slow connect to DB from PID X" | net_trace | `--pid=X` | `connect_latency_ns`,`tcp_state`,`retrans_out` |
| 6 | "openat latency for PID X" | trace_syscall | `--syscall=openat --pid=X` | `duration_ns` |
| 7 | "PID X CPU-starved, low usage" | runq_lat | `--pid=X --timeout=3` | `runq_ns` |
| 8 | "RCA do_sys_openat2 return codes" | attach | `--function=do_sys_openat2 --mode=kprobe_kretprobe` | `retval`,`phase` |
| 9 | "uprobe SSL_read in PID X" | attach_uprobe | `--target=libssl:SSL_read --pid=X` | `retval`,`phase` |
| 10 | "list tcp_ attachable symbols" | list_attachable | `--filter=tcp_ --max=20 --type=t` (columns) | `NAME` |

# PASS = model picks the row's capability AND the decisive params (esp. --pid, and
# fs_op=fault / correct --syscall / --function). Common FAILS to catch:
#  - forgetting --verify-image=false (image error)
#  - using --ksym_filter instead of --filter for list_attachable
#  - reading top-level comm instead of proc.comm in -o json
#  - not scoping runq_lat (flood)
