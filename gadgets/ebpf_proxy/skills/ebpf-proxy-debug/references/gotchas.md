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
event output. Therefore uprobe-backed capabilities (`heap_profile`, `lock_trace`,
`cuda_memtrace`, `cuda_profile`, and explicit `attach_uprobe`) require both
selectors with the same verified process identity:

```bash
--pid=<PID> --operator.oci.wasm.pid=<PID>
```

Using only gadget `--pid` can report `attached_count > 0` after attaching libc or
CUDA probes to unrelated long-lived host processes; the in-kernel filter then
correctly emits no rows for the requested PID. Treat attachment logs naming
other PIDs as invalid target attachment, not as evidence that the requested
process was observed. Kernel-only capabilities such as `trace_syscall` need only
gadget `--pid`; setting only the operator PID for them yields an unfiltered or
empty result rather than correct event scoping.

## 6. `attach_uprobe` requires the raw linker symbol
Rust and C++ tools often print a readable demangled name containing components
such as `::`. That display name is not the ELF symbol and cannot be used as the
attach target. Resolve and copy the exact non-demangled symbol-table entry:

```bash
nm --no-demangle --defined-only <binary-or-library> | grep '<stable fragment>'
# Use -D as well when the target is a dynamic export:
nm -D --no-demangle --defined-only <library> | grep '<stable fragment>'
```

Legacy Rust raw symbols can contain `$LT$`, `$GT$`, and similar
`$`-delimited components. These are part of the linker symbol and must be
passed unchanged.

Pass the complete name column to `--target=<path>:<symbol>`. `nm -C` is useful
for identifying what a symbol means, but its output must not be copied into the
attach command.

## 7. `ebpf_proxy_coverage`: attached-but-idle vs attach-fail
Every run emits one `ebpf_proxy_coverage` record (`capability`, `attached_targets`,
`attached_count`, `pid_filter`, `note`). `attached_count > 0` with **zero events**
= attached-but-idle: WIDEN `--timeout`/`--pid`; do NOT switch capability. This is
the #1 source of false "it didn't work" only after attachment identity is valid.
For uprobe-backed capabilities, first verify the attachment log names the
requested PID or its mapped executable/library; unrelated attachment PIDs make
the run invalid regardless of `attached_count`.

## 8. High-rate capabilities truncate/flood
`runq_lat` produced **366266 rows in ~6 s**; unfiltered `attach` on a hot symbol
and `trace_syscall` with no `--syscall` are similar. Always scope with `--pid`, a
short `--timeout`, and op-class filters (`fs_op=fault`, `cuda_op=copy`) first.

## 9. NVML per-PID GPU fields are often 0 in containers
`gpu_pid`, `used_gpu_mem`, `sm_util` are frequently structurally empty inside
containers by NVML design — **0 is expected**, not a bug. Use device-level
`dev_total`/`dev_used`/`dev_free`. (GPU details in the `ebpf-proxy-gpu-debug` skill.)

## 10. columns mode prints a header block per datasource
`-o columns` prints a header for EVERY datasource in the gadget (fs/net/heap/runq/
cuda/...) even when only one is active. The real rows are those with data —
prefer `-o json` + field filtering for programmatic use.
