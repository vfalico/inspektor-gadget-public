# migration_scanner

The `migration_scanner` gadget predicts the compatibility of a Linux host with
an immutable container OS (Talos, Flatcar, Bottlerocket, or any custom target
defined via a YAML policy file).

It observes filesystem writes, writable-mmap and link/symlink edge cases,
AF_UNIX socket connects (covering container-runtime and syslog sockets),
kernel module loads, host-level execs, and capability checks.

Host-only filtering is enforced in eBPF via pid-namespace inode comparison.
All classification (BLOCKER / WARNING / COMPATIBLE) happens in userspace
against a per-OS YAML policy file — adding a new target OS requires only a
YAML addition, not a BPF rebuild.

