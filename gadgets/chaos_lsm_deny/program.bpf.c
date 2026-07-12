// SPDX-License-Identifier: Apache-2.0
/* chaos_lsm_deny — process-scoped access denial via BPF-LSM hooks.
 *
 * Denies file_open and socket_connect for a scoped process/container using
 * semantic lsm/* hooks. Because the hook is semantic it catches ALL entry
 * paths (openat2, io_uring) that a syscall-wrapper kprobe would miss.
 *
 * Hooks: lsm/file_open, lsm/socket_connect. Returns -EPERM/-EACCES for tasks
 * in the scoped mount-namespace / PID; every other task is untouched.
 *
 * Requires kernel >= 5.7 AND "bpf" present in the active lsm= list (verify:
 * /sys/kernel/security/lsm). If bpf is absent, attach fails and the loader
 * falls back to the kprobe path (chaos_syscall_fail).
 *
 * VERIFIER NOTE (BPF-LSM return-code rule): an lsm/* program's return value
 * MUST be provably within [-4095, 0] (0 == allow, negative == -errno). A bare
 * `return c->errno_val;` (a __s32 map load) is seen by the verifier as an
 * unbounded scalar(0..0xffffffff) and is REJECTED with
 *   "At program exit the register R0 ... should have been in [-4095, 0]".
 * clamp_deny() below recovers the errno magnitude and masks it to 12 bits so
 * the return is provably in [-4095, -1]. The `if (ret) return ret;` early-out
 * is fine because the incoming `ret` arg is already bounded [-4095, 0].
 *
 * Copyright 2026 The Inspektor Gadget authors
 */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

struct cfg_t {
	__u64 target_mntns;
	__u32 target_pid;
	__s32 errno_val;   /* stored NEGATIVE, e.g. -1 EPERM, -13 EACCES */
	__u32 enabled;
	__u32 hook_mask;   /* bit0 file_open bit1 socket_connect */
	__u64 hits;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct cfg_t);
} cfg SEC(".maps");

struct deny_event {
	__u64 ts; __u32 pid, tgid; __u64 mntns; __s32 errno_val; __u32 hook; char comm[16];
};
struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 1<<16); } events SEC(".maps");

#define H_OPEN 0x1
#define H_CONNECT 0x2

static __always_inline struct cfg_t *getcfg(void){ __u32 k=0; return bpf_map_lookup_elem(&cfg,&k); }
static __always_inline __u64 mntns(void){
	struct task_struct *t=(struct task_struct*)bpf_get_current_task();
	return BPF_CORE_READ(t,nsproxy,mnt_ns,ns.inum);
}

/* Verifier-safe deny code: magnitude = (-errno_val) & 0xfff  -> [0,4095];
 * guard 0 -> 1 so a deny never accidentally returns 0 (=allow); negate. */
static __always_inline int clamp_deny(struct cfg_t *c){
	int mag = (-c->errno_val) & 0xfff;
	if (mag == 0) mag = 1;              /* EPERM fallback */
	return -mag;                        /* provably in [-4095, -1] */
}

static __always_inline int scoped(struct cfg_t *c,__u32 bit,__u32 hookid){
	if(!c||!c->enabled) return 0;
	if(!(c->hook_mask&bit)) return 0;
	__u64 pt=bpf_get_current_pid_tgid(); __u32 tgid=pt>>32;
	if(c->target_pid && tgid!=c->target_pid) return 0;
	if(c->target_mntns && mntns()!=c->target_mntns) return 0;
	struct deny_event *e=bpf_ringbuf_reserve(&events,sizeof(*e),0);
	if(e){ e->ts=bpf_ktime_get_ns(); e->pid=(__u32)pt; e->tgid=tgid; e->mntns=mntns();
		e->errno_val=c->errno_val; e->hook=hookid; bpf_get_current_comm(&e->comm,sizeof(e->comm));
		bpf_ringbuf_submit(e,0); }
	__sync_fetch_and_add(&c->hits,1);
	return 1;
}

/* file_open: fires for open/openat/openat2/io_uring open — the semantic op. */
SEC("lsm/file_open")
int BPF_PROG(deny_open, struct file *file, int ret)
{
	if (ret) return ret;                 /* respect earlier LSM denials */
	struct cfg_t *c=getcfg();
	if (scoped(c,H_OPEN,0)) return clamp_deny(c);
	return 0;
}

/* socket_connect: fires for connect() and io_uring connect. */
SEC("lsm/socket_connect")
int BPF_PROG(deny_connect, struct socket *sock, struct sockaddr *address, int addrlen, int ret)
{
	if (ret) return ret;
	struct cfg_t *c=getcfg();
	if (scoped(c,H_CONNECT,1)) return clamp_deny(c);
	return 0;
}
