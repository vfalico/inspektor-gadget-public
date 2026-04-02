// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2025 The Inspektor Gadget authors */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <gadget/types.h>
#include <gadget/common.h>
#include <gadget/filter.h>
#include <gadget/macros.h>
#include <gadget/user_stack_map.h>

#define MAX_ENTRIES 10240
#define MAX_VRAM_ENTRIES 4096

enum memop {
	cuMemAlloc,
	cuMemFree,
	cuMemAllocHost,
	cuMemFreeHost,
	cuMemAllocManaged,
	cuMemAllocPitch,
	cuMemAlloc3D,
};

/* ===== VRAM Allocation Lifecycle Tracking ===== */

/*
 * Core tracking structure for each device memory allocation.
 * Inserted on successful cuMemAlloc (and variants), looked up on
 * memcpy/memset/launch to mark as "used", removed on cuMemFree.
 */
struct vram_alloc_info {
	__u64 devptr;
	__u64 size;
	__u64 alloc_ts;
	__u32 used;       /* 0 = never accessed, 1 = accessed */
	__u32 pid;
	struct gadget_process proc;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_VRAM_ENTRIES);
	__type(key, __u64);              /* device pointer */
	__type(value, struct vram_alloc_info);
} vram_tracker SEC(".maps");

/*
 * Scratch space to carry the userspace dptr address and requested size
 * from uprobe (entry) to uretprobe (return) of allocation calls.
 * Keyed by thread ID — a thread can only be in one call at a time.
 */
struct alloc_scratch {
	__u64 dptr_user_addr;
	__u64 size;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32);
	__type(value, struct alloc_scratch);
} alloc_scratch_map SEC(".maps");

/* Per-CPU heap maps — BPF stack is limited to 512 bytes */
struct heap_vram {
	struct vram_alloc_info info;
};

struct heap_devptr {
	__u64 devptr;
};

/* used for context between uprobes and uretprobes of allocations */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32); // tid
	__type(value, u64);
} sizes SEC(".maps");

struct alloc_key {
	__u32 stack_id_key;
};

struct alloc_val {
	__u64 count;
	struct gadget_process proc;
	struct gadget_user_stack ustack_raw;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct alloc_key);
	__type(value, struct alloc_val);
} allocs SEC(".maps");

/*
 * Heap-allocated scratch space to avoid blowing the 256-byte stack limit
 * required for tail calls. struct alloc_val (~152 B) and
 * struct gadget_user_stack (~64 B) are too large to live on the BPF stack.
 */
struct heap_data {
	struct gadget_user_stack ustack;
	struct alloc_val val;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct heap_data);
} heap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct heap_vram);
} heap_vram_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct heap_devptr);
} heap_devptr_map SEC(".maps");

GADGET_MAPITER(allocs, allocs);

/**
 * clean up the maps when a thread terminates,
 * because there may be residual data in the map
 * if a userspace thread is killed between a uprobe and a uretprobe
 */
SEC("tracepoint/sched/sched_process_exit")
int trace_sched_process_exit(void *ctx)
{
	u32 tid;

	tid = (u32)bpf_get_current_pid_tgid();
	bpf_map_delete_elem(&sizes, &tid);
	bpf_map_delete_elem(&alloc_scratch_map, &tid);
	return 0;
}

static __always_inline int gen_alloc_enter(size_t size)
{
	u32 tid;

	tid = (u32)bpf_get_current_pid_tgid();
	bpf_map_update_elem(&sizes, &tid, &size, BPF_ANY);

	return 0;
}

static __always_inline int gen_alloc_exit(struct pt_regs *ctx,
					  enum memop operation)
{
	u64 pid_tgid;
	u32 tid;
	u64 *size_ptr;
	u64 size;
	int ret;

	// Ignore failed allocations (CUDA_SUCCESS = 0)
	ret = PT_REGS_RC(ctx);
	if (ret != 0)
		return 0;

	if (gadget_should_discard_data_current())
		return 0;

	pid_tgid = bpf_get_current_pid_tgid();
	tid = (u32)pid_tgid;
	size_ptr = bpf_map_lookup_elem(&sizes, &tid);
	if (!size_ptr)
		return 0;
	size = *size_ptr;
	bpf_map_delete_elem(&sizes, &tid);

	struct gadget_user_stack ustack_raw;
	gadget_get_user_stack(ctx, &ustack_raw);

	struct alloc_key key = {
		.stack_id_key = ustack_raw.stack_id,
	};

	struct alloc_val *val = bpf_map_lookup_elem(&allocs, &key);
	if (!val) {
		struct alloc_val new_val = {
			.count = size,
			.ustack_raw = ustack_raw,
		};

		gadget_process_populate(&new_val.proc);

		bpf_map_update_elem(&allocs, &key, &new_val, BPF_NOEXIST);
	} else {
		__sync_fetch_and_add(&val->count, size);
	}

	return 0;
}

/*
 * cuMemAlloc_v2 - Allocate device memory (CUDA Driver API)
 * CUresult cuMemAlloc_v2(CUdeviceptr *dptr, size_t bytesize)
 */
SEC("uprobe/libcuda:cuMemAlloc_v2")
int BPF_UPROBE(trace_uprobe_cuMemAlloc_v2, void **dptr, size_t bytesize)
{
	return gen_alloc_enter(bytesize);
}

SEC("uretprobe/libcuda:cuMemAlloc_v2")
int trace_uretprobe_cuMemAlloc_v2(struct pt_regs *ctx)
{
	return gen_alloc_exit(ctx, cuMemAlloc);
}

/*
 * cuMemAllocHost_v2 - Allocate page-locked host memory (CUDA Driver API)
 * CUresult cuMemAllocHost_v2(void **pp, size_t bytesize)
 */
SEC("uprobe/libcuda:cuMemAllocHost_v2")
int BPF_UPROBE(trace_uprobe_cuMemAllocHost_v2, void **pp, size_t bytesize)
{
	return gen_alloc_enter(bytesize);
}

SEC("uretprobe/libcuda:cuMemAllocHost_v2")
int trace_uretprobe_cuMemAllocHost_v2(struct pt_regs *ctx)
{
	return gen_alloc_exit(ctx, cuMemAllocHost);
}

/*
 * cuMemAllocManaged - Allocate managed memory (CUDA Driver API)
 * CUresult cuMemAllocManaged(CUdeviceptr *dptr, size_t bytesize, unsigned int flags)
 */
SEC("uprobe/libcuda:cuMemAllocManaged")
int BPF_UPROBE(trace_uprobe_cuMemAllocManaged, void **dptr, size_t bytesize,
	       unsigned int flags)
{
	return gen_alloc_enter(bytesize);
}

SEC("uretprobe/libcuda:cuMemAllocManaged")
int trace_uretprobe_cuMemAllocManaged(struct pt_regs *ctx)
{
	return gen_alloc_exit(ctx, cuMemAllocManaged);
}

/*
 * cuMemAllocPitch_v2 - Allocate pitched device memory (CUDA Driver API)
 * CUresult cuMemAllocPitch_v2(CUdeviceptr *dptr, size_t *pPitch, size_t WidthInBytes, size_t Height, unsigned int ElementSizeBytes)
 */
SEC("uprobe/libcuda:cuMemAllocPitch_v2")
int BPF_UPROBE(trace_uprobe_cuMemAllocPitch_v2, void **dptr, size_t *pPitch,
	       size_t WidthInBytes, size_t Height,
	       unsigned int ElementSizeBytes)
{
	size_t size = WidthInBytes * Height; // Approximate size
	return gen_alloc_enter(size);
}

SEC("uretprobe/libcuda:cuMemAllocPitch_v2")
int trace_uretprobe_cuMemAllocPitch_v2(struct pt_regs *ctx)
{
	return gen_alloc_exit(ctx, cuMemAllocPitch);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
