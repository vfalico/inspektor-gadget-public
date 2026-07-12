// SPDX-License-Identifier: Apache-2.0
/* chaos_syscall_fail — inject syscall failures for a scoped process/container.
 *
 * kprobe + bpf_override_return() on the syscall entry wrappers (__x64_sys_*),
 * returning a caller-chosen errno. Scoped by mount namespace (container)
 * and/or PID so a sibling process is provably untouched.
 *
 * Requires: CONFIG_BPF_KPROBE_OVERRIDE=y and the target fn tagged
 * ALLOW_ERROR_INJECTION (verify: /sys/kernel/debug/error_injection/list).
 * bpf_override_return() forces GPL.
 *
 * Runtime-reconfigurable: the loader flips cfg.enabled and rewrites cfg.errno
 * live, no reload needed.
 *
 * Copyright 2026 The Inspektor Gadget authors
 */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

struct cfg_t {
	__u64 target_mntns; /* 0 = any mount namespace */
	__u32 target_pid;   /* 0 = any tgid           */
	__s32 errno_val;    /* negative, e.g. -1 == -EPERM */
	__u32 enabled;      /* runtime on/off toggle  */
	__u32 hook_mask;    /* bit0 open* bit1 connect bit2 read */
	__u64 hits;         /* observability counter  */
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct cfg_t);
} cfg SEC(".maps");

/* event stream so live observability can see each injected fault */
struct fault_event {
	__u64 ts;
	__u32 pid;
	__u32 tgid;
	__u64 mntns;
	__s32 errno_val;
	__u32 hook; /* 0 open 1 openat 2 openat2 3 connect 4 read */
	char comm[16];
};
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 16);
} events SEC(".maps");

#define HOOK_OPEN    0x1
#define HOOK_CONNECT 0x2
#define HOOK_READ    0x4

static __always_inline struct cfg_t *getcfg(void)
{
	__u32 k = 0;
	return bpf_map_lookup_elem(&cfg, &k);
}

static __always_inline __u64 current_mntns(void)
{
	struct task_struct *t = (struct task_struct *)bpf_get_current_task();
	return BPF_CORE_READ(t, nsproxy, mnt_ns, ns.inum);
}

/* returns 1 if this task is in scope and the fault is enabled for this hook */
static __always_inline int in_scope(struct cfg_t *c, __u32 hookbit, __u32 hookid)
{
	if (!c || !c->enabled)
		return 0;
	if (!(c->hook_mask & hookbit))
		return 0;
	__u64 pt = bpf_get_current_pid_tgid();
	__u32 tgid = pt >> 32;
	if (c->target_pid && tgid != c->target_pid)
		return 0;
	if (c->target_mntns && current_mntns() != c->target_mntns)
		return 0;

	struct fault_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (e) {
		e->ts = bpf_ktime_get_ns();
		e->pid = (__u32)pt;
		e->tgid = tgid;
		e->mntns = current_mntns();
		e->errno_val = c->errno_val;
		e->hook = hookid;
		bpf_get_current_comm(&e->comm, sizeof(e->comm));
		bpf_ringbuf_submit(e, 0);
	}
	__sync_fetch_and_add(&c->hits, 1);
	return 1;
}

/* --- syscall entry wrappers (x86_64). All are ALLOW_ERROR_INJECTION=ERRNO. --- */
SEC("kprobe/__x64_sys_openat")
int BPF_KPROBE(k_openat)
{
	struct cfg_t *c = getcfg();
	if (in_scope(c, HOOK_OPEN, 1))
		bpf_override_return(ctx, c->errno_val);
	return 0;
}

SEC("kprobe/__x64_sys_openat2")
int BPF_KPROBE(k_openat2)
{
	struct cfg_t *c = getcfg();
	if (in_scope(c, HOOK_OPEN, 2))
		bpf_override_return(ctx, c->errno_val);
	return 0;
}

SEC("kprobe/__x64_sys_open")
int BPF_KPROBE(k_open)
{
	struct cfg_t *c = getcfg();
	if (in_scope(c, HOOK_OPEN, 0))
		bpf_override_return(ctx, c->errno_val);
	return 0;
}

SEC("kprobe/__x64_sys_connect")
int BPF_KPROBE(k_connect)
{
	struct cfg_t *c = getcfg();
	if (in_scope(c, HOOK_CONNECT, 3))
		bpf_override_return(ctx, c->errno_val);
	return 0;
}

SEC("kprobe/__x64_sys_read")
int BPF_KPROBE(k_read)
{
	struct cfg_t *c = getcfg();
	if (in_scope(c, HOOK_READ, 4))
		bpf_override_return(ctx, c->errno_val);
	return 0;
}
