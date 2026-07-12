# chaos_syscall_fail

Inject a caller-chosen `errno` into a **scoped** process's syscalls using a
kprobe on the syscall entry wrapper plus `bpf_override_return()`. Scope by
mount namespace (container) and/or PID so sibling processes are provably
untouched.

## How it works

`bpf_override_return()` is attached to the `__x64_sys_*` entry wrappers
(`__x64_sys_openat`, `__x64_sys_openat2`, `__x64_sys_open`, `__x64_sys_connect`,
`__x64_sys_read`). When a task in scope calls one of them, the probe forces the
configured negative errno as the return value; the real syscall body never runs.

Every injected fault is emitted on the `events` ring buffer for 1:1 provenance.

## Requirements

- `CONFIG_BPF_KPROBE_OVERRIDE=y`
- The target symbol must be tagged `ALLOW_ERROR_INJECTION` — verify against
  `/sys/kernel/debug/error_injection/list`. Note: only the `__x64_sys_*` entry
  wrappers are injectable; deeper functions such as `do_sys_openat2` are **not**.
- Because `bpf_override_return()` is GPL-only, the program declares `GPL`.

## Parameters

| key | default | meaning |
|-----|---------|---------|
| `pid` | 0 | scope to this PID/TGID (0 = any) |
| `mntns` | 0 | scope to this mount-namespace inode (0 = any) |
| `errno` | -1 | negative errno to inject (-1 EPERM, -13 EACCES, ...) |
| `hooks` | 1 | bitmask: bit0 open\* bit1 connect bit2 read |
| `enable` | true | arm the fault |

## Runtime adjustability

`errno` and `enable` live in the `cfg` BPF map, so an in-flight experiment can
be re-tuned (change errno, disarm) with no reload.

## References

- kernel fault injection: https://docs.kernel.org/fault-injection/index.html
- `bpf_override_return`: https://docs.ebpf.io/linux/helper-function/bpf_override_return/
