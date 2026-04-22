// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2026 The Inspektor Gadget authors
 *
 * gpu_mem_max — track GPU VRAM high-water mark per process/container.
 *
 * Emits ALLOC/FREE events for cuMemAlloc_v2, cuMemAllocPitch_v2,
 * cuMemCreate, cuMemAllocManaged, cuMemFree_v2.  Aggregates per PID
 * into running_sum and high_water maps.  Userspace (operator_nvml_mem.go)
 * adds SNAPSHOT/MAX_REPORT/SIGNAL_LOSS events from NVML + map scanning.
 */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <gadget/types.h>
#include <gadget/common.h>
#include <gadget/filter.h>
#include <gadget/macros.h>
#include <gadget/mntns_filter.h>

#define MAX_ALLOCS   (1 << 20)   /* 1M concurrent allocations */
#define MAX_PROCS    4096

enum event_type_raw {
	EV_ALLOC       = 1,
	EV_FREE        = 2,
	EV_SNAPSHOT    = 3,
	EV_MAX_REPORT  = 4,
	EV_SIGNAL_LOSS = 5,
};

enum api_id {
	API_cuMemAlloc_v2       = 1,
	API_cuMemAllocPitch_v2  = 2,
	API_cuMemCreate         = 3,
	API_cuMemAllocManaged   = 4,
	API_cuMemFree_v2        = 5,
};

struct alloc_key {
	__u64 pid;
	__u64 address;
};

/* LRU so stale entries from dead processes get reclaimed */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, MAX_ALLOCS);
	__type(key, struct alloc_key);
	__type(value, __u64);   /* size in bytes */
} alloc_by_addr SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_PROCS);
	__type(key, __u32);
	__type(value, __u64);
} running_sum SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_PROCS);
	__type(key, __u32);
	__type(value, __u64);
} high_water SEC(".maps");

/* Per-tid scratch map for uprobe->uretprobe handoff */
struct pending_alloc {
	__u64 size;
	__u64 dptr_ptr;    /* &dptr from cuMemAlloc_v2 first arg */
	__u32 api;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, __u64);    /* tid */
	__type(value, struct pending_alloc);
} pending SEC(".maps");

/* Signal-loss flag: set by BPF when a map update fails (map full) */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} map_full_flag SEC(".maps");

struct gpu_mem_event {
	__u32 type;
	__u32 gpu_device;
	__u64 timestamp_ns;

	__u64 size_bytes;
	__u64 address;
	__u32 pid;
	__u32 tid;
	gadget_mntns_id mntns_id;
	__u32 error;
	__u32 api_id;

	__u64 nvml_total_capacity;
	__u64 nvml_total_used;
	__u64 nvml_total_free;
	__u64 nvml_reserved;
	__u64 tracked_sum_all;
	__u64 max_used_seen;

	__u64 container_max_bytes;
	__u64 container_alloc_count;
	__u64 container_free_count;
	char  container[64];
	char  pod[64];
	char  namespace_[64];

	__u64 loss_bytes;
	__u32 loss_pct_x100;
	__u32 confidence;     /* 2=HIGH, 1=MEDIUM, 0=LOW */
	char  loss_reason[128];
};

GADGET_TRACER_MAP(events, 1024 * 256);
GADGET_TRACER(gpu_mem, events, gpu_mem_event);

static __always_inline void set_map_full(void)
{
	__u32 k = 0, v = 1;
	bpf_map_update_elem(&map_full_flag, &k, &v, BPF_ANY);
}

static __always_inline void
emit(__u32 type, __u32 api, __u64 size, __u64 addr, __u32 err)
{
	struct gpu_mem_event *e;
	__u64 id = bpf_get_current_pid_tgid();
	__u32 pid = id >> 32, tid = (__u32)id;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return;
	__builtin_memset(e, 0, sizeof(*e));
	e->type = type;
	e->api_id = api;
	e->size_bytes = size;
	e->address = addr;
	e->error = err;
	e->pid = pid;
	e->tid = tid;
	e->timestamp_ns = bpf_ktime_get_ns();
	e->mntns_id = (gadget_mntns_id)gadget_get_current_mntns_id();
	bpf_ringbuf_submit(e, 0);
}

static __always_inline void
account_alloc(__u32 pid, __u64 addr, __u64 size)
{
	struct alloc_key k = { .pid = pid, .address = addr };
	__u64 cur = 0, *p;
	long r;

	r = bpf_map_update_elem(&alloc_by_addr, &k, &size, BPF_ANY);
	if (r < 0) { set_map_full(); return; }

	p = bpf_map_lookup_elem(&running_sum, &pid);
	if (p) cur = *p;
	cur += size;
	bpf_map_update_elem(&running_sum, &pid, &cur, BPF_ANY);

	p = bpf_map_lookup_elem(&high_water, &pid);
	if (!p || *p < cur)
		bpf_map_update_elem(&high_water, &pid, &cur, BPF_ANY);
}

static __always_inline void
account_free(__u32 pid, __u64 addr)
{
	struct alloc_key k = { .pid = pid, .address = addr };
	__u64 *pz, size, cur;

	pz = bpf_map_lookup_elem(&alloc_by_addr, &k);
	if (!pz) return;        /* alloc pre-existed gadget attach */
	size = *pz;
	bpf_map_delete_elem(&alloc_by_addr, &k);

	pz = bpf_map_lookup_elem(&running_sum, &pid);
	if (!pz) return;
	cur = *pz;
	if (cur >= size) cur -= size; else cur = 0;
	bpf_map_update_elem(&running_sum, &pid, &cur, BPF_ANY);
}

/* ── cuMemAlloc_v2(CUdeviceptr *dptr, size_t bytesize) ─────────────── */

SEC("uprobe//usr/local/cuda/lib64/libcuda.so.1:cuMemAlloc_v2")
int BPF_UPROBE(cu_mem_alloc_v2_enter, __u64 dptr_arg, __u64 size)
{
	if (gadget_should_discard_mntns_id(gadget_get_current_mntns_id()))
		return 0;
	__u64 tid = bpf_get_current_pid_tgid();
	struct pending_alloc p = {
		.size = size, .dptr_ptr = dptr_arg, .api = API_cuMemAlloc_v2,
	};
	bpf_map_update_elem(&pending, &tid, &p, BPF_ANY);
	return 0;
}

SEC("uretprobe//usr/local/cuda/lib64/libcuda.so.1:cuMemAlloc_v2")
int BPF_URETPROBE(cu_mem_alloc_v2_exit, int rc)
{
	__u64 tid = bpf_get_current_pid_tgid();
	__u32 pid = tid >> 32;
	struct pending_alloc *p = bpf_map_lookup_elem(&pending, &tid);
	if (!p) return 0;

	__u64 addr = 0;
	if (rc == 0)
		bpf_probe_read_user(&addr, sizeof(addr), (void *)p->dptr_ptr);

	if (rc == 0 && addr && p->size) {
		account_alloc(pid, addr, p->size);
		emit(EV_ALLOC, p->api, p->size, addr, 0);
	} else {
		emit(EV_ALLOC, p->api, p->size, 0, rc);
	}
	bpf_map_delete_elem(&pending, &tid);
	return 0;
}

/* ── cuMemAllocManaged(CUdeviceptr *dptr, size_t, unsigned flags) ──── */

SEC("uprobe//usr/local/cuda/lib64/libcuda.so.1:cuMemAllocManaged")
int BPF_UPROBE(cu_mem_alloc_managed_enter, __u64 dptr_arg, __u64 size)
{
	if (gadget_should_discard_mntns_id(gadget_get_current_mntns_id()))
		return 0;
	__u64 tid = bpf_get_current_pid_tgid();
	struct pending_alloc p = {
		.size = size, .dptr_ptr = dptr_arg, .api = API_cuMemAllocManaged,
	};
	bpf_map_update_elem(&pending, &tid, &p, BPF_ANY);
	return 0;
}

SEC("uretprobe//usr/local/cuda/lib64/libcuda.so.1:cuMemAllocManaged")
int BPF_URETPROBE(cu_mem_alloc_managed_exit, int rc)
{
	return cu_mem_alloc_v2_exit(ctx, rc);
}

/* ── cuMemFree_v2(CUdeviceptr dptr) ─────────────────────────────────── */

SEC("uprobe//usr/local/cuda/lib64/libcuda.so.1:cuMemFree_v2")
int BPF_UPROBE(cu_mem_free_v2_enter, __u64 dptr)
{
	if (gadget_should_discard_mntns_id(gadget_get_current_mntns_id()))
		return 0;
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	struct alloc_key k = { .pid = pid, .address = dptr };
	__u64 *pz = bpf_map_lookup_elem(&alloc_by_addr, &k);
	__u64 size = pz ? *pz : 0;
	account_free(pid, dptr);
	emit(EV_FREE, API_cuMemFree_v2, size, dptr, 0);
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
