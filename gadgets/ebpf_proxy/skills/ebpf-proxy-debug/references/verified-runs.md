# eBPF Proxy verified runs — copy-paste commands with REAL captured output

All captured on **slavanestedvm** (kernel 6.17.0-1018-azure, Ubuntu 24.04,
image `ebpf_proxy:latest`) via plain `ig run` — no MCP server. Row counts are
the actual events captured in a short window against a synthetic workload
(`workload.py`: fails to open `/etc/myapp/missing.conf`, connects to a refused
localhost port, mallocs, spins).

## fs_trace (failing opens) — 578 events
```bash
sudo ig run ebpf_proxy:latest --verify-image=false \
  --capability=fs_trace --fs_op=fault --pid=<PID> --timeout=6 -o json
```
Real event + coverage:
```json
{"comm":"python3","pid":55577,"fname":"/etc/myapp/missing.conf","retval":-2,"fs_op":"fs_filp_open","count":0}
ebpf_proxy_coverage: {"capability":"fs_trace","attached_count":8,"pid_filter":55577,
  "attached_targets":"ebpf_proxy_fs_read,ebpf_proxy_fs_read_ret,ebpf_proxy_fs_write,ebpf_proxy_fs_write_ret,ebpf_proxy_fs_open,ebpf_proxy_fs_open_ret,ebpf_proxy_fs_filp_open,ebpf_proxy_fs_filp_open_ret"}
```
`retval:-2` = ENOENT. Fix: create the file / correct the path, re-run -> 0 rows.

## net_trace (connect/retransmit) — 577 events
```bash
sudo ig run ebpf_proxy:latest --verify-image=false \
  --capability=net_trace --pid=<PID> --timeout=6 -o json
```
```json
{"comm":"python3","dport":9,"sport":54342,"tcp_state":2,"retval":0,"net_op":"net_connect","connect_latency_ns":88995}
```
`dport:9` (discard) refused; `connect_latency_ns` is the connect cost.

## trace_syscall (per-syscall latency) — 2308 events
```bash
sudo ig run ebpf_proxy:latest --verify-image=false \
  --capability=trace_syscall --syscall=openat --pid=<PID> --timeout=6 -o json
```
```json
{"comm":"python3","pid":55577,"syscall":"SYS_OPENAT","retval":0,"duration_ns":0}
```
`syscall` is DECODED to the name. Aggregate `duration_ns` for latency.

## attach (raw kprobe/kretprobe on a kernel symbol) — 13362 events
```bash
sudo ig run ebpf_proxy:latest --verify-image=false \
  --capability=attach --function=do_sys_openat2 --mode=kprobe_kretprobe \
  --pid=<PID> --timeout=6 -o json
```
```json
{"comm":"python3","func":"do_sys_openat2","retval":0,"phase":"enter","arg0":4294967196}
```
`phase` = enter (kprobe) / ret (kretprobe). Validate the symbol via
`list_attachable` first.

## heap_profile (libc malloc/free) — system-wide
```bash
sudo ig run ebpf_proxy:latest --verify-image=false \
  --capability=heap_profile --pid=<PID> \
  --operator.oci.wasm.pid=<PID> --timeout=6 -o json
```
```json
{"size":null,"ptr":null,"heap_op":null,"proc.comm":null}   # sample; attaches 9 uprobes
ebpf_proxy_coverage: attached_count=9 (malloc/calloc/realloc/free/brk/mmap + rets)
```
With a tight pid + short window you may see only the coverage row
(attached-but-idle) after verifying that the uprobe attachment log names that
PID or its mapped libc. Widen the window only after that identity check.

## runq_lat (scheduler run-queue latency) — 366266 events in ~6 s (HIGH RATE)
```bash
sudo ig run ebpf_proxy:latest --verify-image=false \
  --capability=runq_lat --pid=<PID> --timeout=3 -o json    # ALWAYS scope
```
```json
{"comm":"swapper/22","cpu":22,"runq_ns":4197,"runq_lat_ns":null}
```
Unscoped this floods — filter by `--pid` and a short `--timeout`.

## list_attachable (enumerate kprobe-able symbols) — columns mode
```bash
sudo ig run ebpf_proxy:latest --verify-image=false \
  --capability=list_attachable --filter=tcp_v4 --max=8 --type=t -o columns
```
Output (TYPE NAME MODULE; TYPE 116 = 't' = function):
```
116  tcp_v4_init_seq
116  tcp_v4_init_sock
116  tcp_v4_pre_connect
```
Flags are `--filter/--max/--type` (NOT `--ksym_*`). Use columns, not json, here.
