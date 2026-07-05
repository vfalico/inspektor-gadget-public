# eBPF Proxy gotchas (each verified on slavanestedvm, kernel 6.17.0-1018-azure)

## 1. Signature verification blocks local images
A locally-built/unsigned image fails with
`pulling signing information ... 401 unauthorized`.
**Fix:** always pass `--verify-image=false` for local images.

## 2. `list_attachable` flag names differ from the display names
The gadget.yaml *display names* are `ksym_filter`, `ksym_max`, `ksym_type`, but
the CLI flags are the `key:` fields: **`--filter`**, **`--max`**, **`--type`**.
`--ksym_filter` errors `unknown flag: --ksym_filter`. Confirm with
`ig run ebpf_proxy:latest --verify-image=false --help`.

## 3. `list_attachable` renders in columns, not JSON events
Symbols come out on the `symbols` datasource as `TYPE NAME MODULE`. In this build
`-o columns` shows them; `-o json` emitted 0 event lines for that datasource.
`TYPE` is the kallsyms type as a byte: **116 = ASCII 't' = text/function**.
Use `--type=t` to keep only functions. Do NOT pass a tiny `--timeout` —
enumeration needs a moment.

## 4. `-o json` nests process identity under `proc.*`
`proc.comm`, `proc.pid`, `proc.tid`, `proc.parent.comm`, `proc.creds.uid`.
A naive top-level `row["comm"]` is `None`. `-o columns` flattens to `COMM`/`PID`.
`scripts/ebpf-proxy-summarize.py` resolves both shapes.

## 5. `--pid` (gadget) vs `operator.oci.wasm.pid`
Use the gadget `--pid` to FILTER EVENTS (in-kernel `filter_pid` map). The WASM
operator's `pid` param only scopes uprobe ATTACH resolution — it does not filter
event output.

## 6. `ebpf_proxy_coverage`: attached-but-idle vs attach-fail
Every run emits one `ebpf_proxy_coverage` record (`capability`, `attached_targets`,
`attached_count`, `pid_filter`, `note`). `attached_count > 0` with **zero events**
= attached-but-idle: WIDEN `--timeout`/`--pid`; do NOT switch capability. This is
the #1 source of false "it didn't work".

## 7. High-rate capabilities truncate/flood
`runq_lat` produced **366266 rows in ~6 s**; unfiltered `attach` on a hot symbol
and `trace_syscall` with no `--syscall` are similar. Always scope with `--pid`, a
short `--timeout`, and op-class filters (`fs_op=fault`, `cuda_op=copy`) first.

## 8. NVML per-PID GPU fields are often 0 in containers
`gpu_pid`, `used_gpu_mem`, `sm_util` are frequently structurally empty inside
containers by NVML design — **0 is expected**, not a bug. Use device-level
`dev_total`/`dev_used`/`dev_free`. (GPU details in the `ebpf-proxy-gpu-debug` skill.)

## 9. columns mode prints a header block per datasource
`-o columns` prints a header for EVERY datasource in the gadget (fs/net/heap/runq/
cuda/...) even when only one is active. The real rows are those with data —
prefer `-o json` + field filtering for programmatic use.
