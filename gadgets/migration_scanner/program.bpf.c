// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2026 The Inspektor Gadget authors
//
// migration_scanner — eBPF program for immutable OS migration readiness.
//
// Hooks:
//   - sys_enter_openat      : detect writes under read-only trees
//   - sys_enter_mkdirat     : detect directory creation under read-only trees
//   - sys_enter_unlinkat    : detect deletions under read-only trees
//   - sys_enter_renameat2   : detect renames under read-only trees
//   - sys_enter_truncate    : detect truncations under read-only trees
//   - sys_enter_mmap        : detect PROT_WRITE mmap of paths under RO trees
//   - sys_enter_linkat      : detect hardlinks crossing boundaries
//   - sys_enter_symlinkat   : detect symlinks pointing into RO tree
//   - sys_enter_connect     : detect AF_UNIX connects (runtime/logging sockets)
//   - sys_enter_finit_module: detect kernel module loads
//   - sys_enter_init_module : detect kernel module loads (legacy path)
//   - sched_process_exec    : detect host-level execs
//   - kprobe/cap_capable    : detect capability usage (sampled)
//
// Generic mechanism: BPF emits raw, neutral, categorised events. All
// classification (BLOCKER/WARNING/COMPATIBLE) happens in userspace against
// a YAML policy file.

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include <gadget/buffer.h>
#include <gadget/macros.h>
#include <gadget/mntns_filter.h>
#include <gadget/types.h>

#ifndef O_WRONLY
#define O_WRONLY 00000001
#define O_RDWR   00000002
#define O_CREAT  00000100
#define O_TRUNC  00001000
#define O_TMPFILE 020200000
#endif
#ifndef AF_UNIX
#define AF_UNIX 1
#endif
#ifndef PROT_WRITE
#define PROT_WRITE 0x2
#endif
#ifndef MAP_SHARED
#define MAP_SHARED 0x01
#endif

#define MAX_PATH 256
#define MAX_COMM 16
#define MAX_ARG  128

enum scope {
	SCOPE_HOST                = 0,
	SCOPE_CONTAINER_HOSTPATH  = 1,
	SCOPE_CONTAINER_INTERNAL  = 2,
};

enum category {
	CAT_FS_WRITE   = 1,
	CAT_SOCKET     = 2,
	CAT_KMOD       = 3,
	CAT_EXEC       = 4,
	CAT_CAPABILITY = 5,
	CAT_SELINUX    = 6,
	CAT_FS_MMAP    = 7,
	CAT_FS_LINK    = 8,
	CAT_FS_SYMLINK = 9,
};

struct event {
	gadget_timestamp ts_raw;
	gadget_mntns_id  mntns_id;
	__u32 pid, tid, ppid, uid, gid;
	__u32 category;
	__u32 scope;
	__u32 syscall_nr;
	__u64 cgroup_id;
	__s32 ret;
	__u32 flags;
	__u32 cap;
	__u8  comm[MAX_COMM];
	__u8  path[MAX_PATH];
	__u8  arg[MAX_ARG];
};

GADGET_TRACER_MAP(events, 1024 * 256);
GADGET_TRACER(migration_scanner, events, event);

const volatile __u64 host_pidns_ino_const = 0;
const volatile __u8  predict_selinux = 0;

#define CAP_SAMPLE_CAP 3
struct cap_key { __u32 tgid; __u32 cap; };
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, struct cap_key);
	__type(value, __u32);
} cap_dedup SEC(".maps");

// Track recent open()-with-write-intent paths per pid for mmap correlation.
struct open_key { __u32 tgid; __u32 fd; };
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, struct open_key);
	__type(value, __u8[MAX_PATH]);
} fd_paths SEC(".maps");

// ── helpers ─────────────────────────────────────────────────────────────

static __always_inline __u64 task_pidns_ino(struct task_struct *task)
{
	struct pid_namespace *pidns;
	pidns = BPF_CORE_READ(task, nsproxy, pid_ns_for_children);
	if (!pidns) return 0;
	return BPF_CORE_READ(pidns, ns.inum);
}

static __always_inline int is_host_task(struct task_struct *task)
{
	if (!host_pidns_ino_const) return 1;
	return task_pidns_ino(task) == host_pidns_ino_const;
}

static __always_inline int classify_scope(struct task_struct *task)
{
	if (is_host_task(task))
		return SCOPE_HOST;
	return SCOPE_CONTAINER_INTERNAL;
}

static __always_inline void fill_common(struct event *e, struct task_struct *task)
{
	__u64 pt = bpf_get_current_pid_tgid();
	e->ts_raw = bpf_ktime_get_boot_ns();
	e->pid = pt >> 32;
	e->tid = (__u32)pt;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	__u64 ug = bpf_get_current_uid_gid();
	e->uid = (__u32)ug;
	e->gid = ug >> 32;
	e->cgroup_id = bpf_get_current_cgroup_id();
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	e->mntns_id = (__u64)BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
	e->ret = 0;
	e->flags = 0;
	e->cap = 0;
	__builtin_memset(e->path, 0, MAX_PATH);
	__builtin_memset(e->arg,  0, MAX_ARG);
}

static __always_inline struct event *reserve_for_host(struct task_struct *task)
{
	int scope = classify_scope(task);
	if (scope == SCOPE_CONTAINER_INTERNAL)
		return NULL;
	struct event *e = gadget_reserve_buf(&events, sizeof(*e));
	if (!e) return NULL;
	fill_common(e, task);
	e->scope = scope;
	return e;
}

// ── FS_WRITE family ─────────────────────────────────────────────────────

SEC("tracepoint/syscalls/sys_enter_openat")
int tp_openat(struct trace_event_raw_sys_enter *ctx)
{
	int flags = (int)ctx->args[2];
	if (!(flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_TMPFILE)))
		return 0;
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct event *e = reserve_for_host(task);
	if (!e) return 0;
	e->category   = CAT_FS_WRITE;
	e->syscall_nr = 257;
	e->flags      = flags;
	bpf_probe_read_user_str(e->path, MAX_PATH, (char *)ctx->args[1]);
	gadget_submit_buf(ctx, &events, e, sizeof(*e));
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_mkdirat")
int tp_mkdirat(struct trace_event_raw_sys_enter *ctx)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct event *e = reserve_for_host(task);
	if (!e) return 0;
	e->category   = CAT_FS_WRITE;
	e->syscall_nr = 258;
	bpf_probe_read_user_str(e->path, MAX_PATH, (char *)ctx->args[1]);
	gadget_submit_buf(ctx, &events, e, sizeof(*e));
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int tp_unlinkat(struct trace_event_raw_sys_enter *ctx)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct event *e = reserve_for_host(task);
	if (!e) return 0;
	e->category   = CAT_FS_WRITE;
	e->syscall_nr = 263;
	bpf_probe_read_user_str(e->path, MAX_PATH, (char *)ctx->args[1]);
	gadget_submit_buf(ctx, &events, e, sizeof(*e));
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_renameat2")
int tp_renameat2(struct trace_event_raw_sys_enter *ctx)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct event *e = reserve_for_host(task);
	if (!e) return 0;
	e->category   = CAT_FS_WRITE;
	e->syscall_nr = 316;
	bpf_probe_read_user_str(e->path, MAX_PATH, (char *)ctx->args[1]);
	bpf_probe_read_user_str(e->arg,  MAX_ARG,  (char *)ctx->args[3]);
	gadget_submit_buf(ctx, &events, e, sizeof(*e));
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_truncate")
int tp_truncate(struct trace_event_raw_sys_enter *ctx)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct event *e = reserve_for_host(task);
	if (!e) return 0;
	e->category   = CAT_FS_WRITE;
	e->syscall_nr = 76;
	bpf_probe_read_user_str(e->path, MAX_PATH, (char *)ctx->args[0]);
	gadget_submit_buf(ctx, &events, e, sizeof(*e));
	return 0;
}

// ── mmap PROT_WRITE on shared mappings ───────────────────────────────────

SEC("tracepoint/syscalls/sys_enter_mmap")
int tp_mmap(struct trace_event_raw_sys_enter *ctx)
{
	int prot  = (int)ctx->args[2];
	int flags = (int)ctx->args[3];
	if (!(prot & PROT_WRITE))
		return 0;
	if (!(flags & MAP_SHARED))
		return 0;
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct event *e = reserve_for_host(task);
	if (!e) return 0;
	e->category   = CAT_FS_MMAP;
	e->syscall_nr = 9;
	e->flags      = flags;
	// fd is in args[4]; userspace operator joins to recent open via fd_paths
	__u32 fd = (__u32)ctx->args[4];
	struct open_key k = { .tgid = e->pid, .fd = fd };
	__u8 *p = bpf_map_lookup_elem(&fd_paths, &k);
	if (p)
		bpf_probe_read_kernel_str(e->path, MAX_PATH, p);
	gadget_submit_buf(ctx, &events, e, sizeof(*e));
	return 0;
}

// ── linkat — hardlink across boundaries ──────────────────────────────────

SEC("tracepoint/syscalls/sys_enter_linkat")
int tp_linkat(struct trace_event_raw_sys_enter *ctx)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct event *e = reserve_for_host(task);
	if (!e) return 0;
	e->category   = CAT_FS_LINK;
	e->syscall_nr = 265;
	bpf_probe_read_user_str(e->path, MAX_PATH, (char *)ctx->args[1]);
	bpf_probe_read_user_str(e->arg,  MAX_ARG,  (char *)ctx->args[3]);
	gadget_submit_buf(ctx, &events, e, sizeof(*e));
	return 0;
}

// ── symlinkat — symlink target into RO tree ──────────────────────────────

SEC("tracepoint/syscalls/sys_enter_symlinkat")
int tp_symlinkat(struct trace_event_raw_sys_enter *ctx)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct event *e = reserve_for_host(task);
	if (!e) return 0;
	e->category   = CAT_FS_SYMLINK;
	e->syscall_nr = 266;
	bpf_probe_read_user_str(e->path, MAX_PATH, (char *)ctx->args[0]); // target
	bpf_probe_read_user_str(e->arg,  MAX_ARG,  (char *)ctx->args[2]); // linkpath
	gadget_submit_buf(ctx, &events, e, sizeof(*e));
	return 0;
}

// ── SOCKET (AF_UNIX connect) ─────────────────────────────────────────────

SEC("tracepoint/syscalls/sys_enter_connect")
int tp_connect(struct trace_event_raw_sys_enter *ctx)
{
	struct sockaddr *uaddr = (struct sockaddr *)ctx->args[1];
	short family = 0;
	bpf_probe_read_user(&family, sizeof(family), uaddr);
	if (family != AF_UNIX) return 0;

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct event *e = reserve_for_host(task);
	if (!e) return 0;
	e->category   = CAT_SOCKET;
	e->syscall_nr = 42;
	bpf_probe_read_user_str(e->path, MAX_PATH, (char *)uaddr + 2);
	if (e->path[0] == 0) {
		gadget_discard_buf(e);
		return 0;
	}
	gadget_submit_buf(ctx, &events, e, sizeof(*e));
	return 0;
}

// ── KMOD ────────────────────────────────────────────────────────────────

SEC("tracepoint/syscalls/sys_enter_finit_module")
int tp_finit(struct trace_event_raw_sys_enter *ctx)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct event *e = gadget_reserve_buf(&events, sizeof(*e));
	if (!e) return 0;
	fill_common(e, task);
	e->scope      = is_host_task(task) ? SCOPE_HOST : SCOPE_CONTAINER_HOSTPATH;
	e->category   = CAT_KMOD;
	e->syscall_nr = 313;
	e->flags      = (int)ctx->args[2];
	bpf_probe_read_user_str(e->arg, MAX_ARG, (char *)ctx->args[1]);
	gadget_submit_buf(ctx, &events, e, sizeof(*e));
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_init_module")
int tp_init_module(struct trace_event_raw_sys_enter *ctx)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct event *e = gadget_reserve_buf(&events, sizeof(*e));
	if (!e) return 0;
	fill_common(e, task);
	e->scope      = is_host_task(task) ? SCOPE_HOST : SCOPE_CONTAINER_HOSTPATH;
	e->category   = CAT_KMOD;
	e->syscall_nr = 175;
	bpf_probe_read_user_str(e->arg, MAX_ARG, (char *)ctx->args[2]);
	gadget_submit_buf(ctx, &events, e, sizeof(*e));
	return 0;
}

// ── EXEC ────────────────────────────────────────────────────────────────

SEC("tracepoint/sched/sched_process_exec")
int tp_sched_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	if (!is_host_task(task)) return 0;

	struct event *e = gadget_reserve_buf(&events, sizeof(*e));
	if (!e) return 0;
	fill_common(e, task);
	e->scope    = SCOPE_HOST;
	e->category = CAT_EXEC;
	unsigned int fname_off = ctx->__data_loc_filename & 0xFFFF;
	bpf_probe_read_kernel_str(e->path, MAX_PATH, (char *)ctx + fname_off);
	gadget_submit_buf(ctx, &events, e, sizeof(*e));
	return 0;
}

// ── CAPABILITY (sampled) ────────────────────────────────────────────────

SEC("kprobe/cap_capable")
int BPF_KPROBE(kp_cap_capable, const struct cred *cred, struct user_namespace *ns,
               int cap, unsigned int opts)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	if (!is_host_task(task)) return 0;

	__u32 tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
	struct cap_key key = { .tgid = tgid, .cap = (__u32)cap };
	__u32 *cnt = bpf_map_lookup_elem(&cap_dedup, &key);
	if (cnt) {
		if (*cnt >= CAP_SAMPLE_CAP) return 0;
		__sync_fetch_and_add(cnt, 1);
	} else {
		__u32 one = 1;
		bpf_map_update_elem(&cap_dedup, &key, &one, BPF_ANY);
	}

	struct event *e = gadget_reserve_buf(&events, sizeof(*e));
	if (!e) return 0;
	fill_common(e, task);
	e->scope    = SCOPE_HOST;
	e->category = CAT_CAPABILITY;
	e->cap      = (__u32)cap;
	gadget_submit_buf(ctx, &events, e, sizeof(*e));
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
