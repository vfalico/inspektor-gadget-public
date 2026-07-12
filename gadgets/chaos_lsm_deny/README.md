# chaos_lsm_deny

Deny `file_open` and `socket_connect` for a **scoped** process/container using
semantic BPF-LSM hooks, returning `-EPERM`/`-EACCES`.

## Why LSM instead of a syscall kprobe

The `lsm/file_open` and `lsm/socket_connect` hooks are **semantic**: they fire
on the underlying operation regardless of entry path (`open`, `openat`,
`openat2`, `io_uring`). A syscall-wrapper kprobe misses the alternative entry
paths; the LSM hook closes that bypass class.

## Verifier note (important)

A BPF-LSM program's return must be provably in `[-4095, 0]` (0 = allow,
negative = `-errno`). A bare `return cfg->errno_val;` (a `__s32` map load) is
seen by the verifier as an unbounded scalar and **rejected**. The gadget masks
the errno magnitude to 12 bits and negates it (`clamp_deny()`), yielding a
provable `[-4095, -1]`. Earlier LSM denials (`ret != 0`) are respected.

## Requirements

- Kernel >= 5.7
- `bpf` present in the active LSM list — verify `/sys/kernel/security/lsm`.
  If `bpf` is absent, attach fails; the reference loader then falls back to
  `chaos_syscall_fail`.

## Parameters

| key | default | meaning |
|-----|---------|---------|
| `pid` | 0 | scope to this PID/TGID (0 = any) |
| `mntns` | 0 | scope to this mount-namespace inode (0 = any) |
| `errno` | -1 | negative errno to return (clamped to [-4095,-1]) |
| `hooks` | 3 | bitmask: bit0 file_open bit1 socket_connect |
| `enable` | true | arm the denial |

## References

- BPF-LSM programs: https://docs.kernel.org/bpf/prog_lsm.html
