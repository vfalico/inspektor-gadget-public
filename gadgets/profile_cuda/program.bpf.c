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

/* Output: allocations that were freed without ever being accessed */
struct unused_alloc_entry {
	struct gadget_process proc;
	__u64 devptr;
	__u64 size;
};

struct unused_key {
	__u64 ptr_id;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_VRAM_ENTRIES);
	__type(key, struct unused_key);
	__type(value, struct unused_alloc_entry);
} unused_allocs SEC(".maps");
GADGET_MAPITER(unused_allocs, unused_allocs);

/* Output: allocations that were used but never freed (traditional leak) */
struct leaked_alloc_entry {
	struct gadget_process proc;
	__u64 devptr;
	__u64 size;
	__u64 alloc_ts;
	__u64 first_use_ts;
	__u32 pid;
};

struct leaked_key {
	__u64 ptr_id;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_VRAM_ENTRIES);
	__type(key, struct leaked_key);
	__type(value, struct leaked_alloc_entry);
} leaked_allocs SEC(".maps");
GADGET_MAPITER(leaked_allocs, leaked_allocs);

/* Output: allocations never used AND never freed (exception-path leak) */
struct exception_alloc_entry {
	struct gadget_process proc;
	__u64 devptr;
	__u64 size;
	__u64 alloc_ts;
	__u32 pid;
};

struct exception_key {
	__u64 ptr_id;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_VRAM_ENTRIES);
	__type(key, struct exception_key);
	__type(value, struct exception_alloc_entry);
} exception_path_allocs SEC(".maps");
GADGET_MAPITER(exception_path_allocs, exception_path_allocs);

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, __u64);
} frag_event_counter SEC(".maps");

/* Per-CPU heap maps — BPF stack is limited to 512 bytes */
struct heap_vram {
	struct vram_alloc_info info;
};

struct heap_devptr {
	__u64 devptr;
};

struct heap_leaked {
	struct leaked_alloc_entry entry;
};

struct heap_exception {
	struct exception_alloc_entry entry;
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

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct heap_leaked);
} heap_leaked_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct heap_exception);
} heap_exception_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct heap_frag);
} heap_frag_map SEC(".maps");

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

/*
 * Combined flamegraph recording + VRAM lifecycle tracking.
 * track_vram: 1 for device allocs, 0 for host-only (cuMemAllocHost).
 */
static __always_inline int gen_alloc_exit_with_vram(struct pt_regs *ctx,
						    enum memop operation,
						    int track_vram)
{
	u64 pid_tgid;
	u32 tid;
	u64 *size_ptr;
	u64 size;
	int ret;

	ret = PT_REGS_RC(ctx);
	pid_tgid = bpf_get_current_pid_tgid();
	tid = (u32)pid_tgid;

	if (ret != 0) {
		/* Clean up scratch on failed alloc */
		bpf_map_delete_elem(&sizes, &tid);
		bpf_map_delete_elem(&alloc_scratch_map, &tid);
		return 0;
	}

	/* VRAM tracking: read device pointer from userspace */
	if (track_vram) {
		struct alloc_scratch *scratch =
			bpf_map_lookup_elem(&alloc_scratch_map, &tid);
		if (scratch) {
			__u64 dptr_addr = scratch->dptr_user_addr;
			__u64 alloc_size = scratch->size;
			bpf_map_delete_elem(&alloc_scratch_map, &tid);

			u32 zero = 0;
			struct heap_devptr *hdp =
				bpf_map_lookup_elem(&heap_devptr_map, &zero);
			if (hdp) {
				hdp->devptr = 0;
				if (bpf_probe_read_user(&hdp->devptr,
							sizeof(__u64),
							(void *)dptr_addr) == 0
				    && hdp->devptr != 0) {
					struct heap_vram *hv =
						bpf_map_lookup_elem(
							&heap_vram_map, &zero);
					if (hv) {
						__builtin_memset(&hv->info, 0,
								 sizeof(hv->info));
						hv->info.devptr = hdp->devptr;
						hv->info.size = alloc_size;
						hv->info.alloc_ts =
							bpf_ktime_get_ns();
						hv->info.used = 0;
						hv->info.pid =
							(u32)(pid_tgid >> 32);
						gadget_process_populate(
							&hv->info.proc);
						bpf_map_update_elem(
							&vram_tracker,
							&hdp->devptr,
							&hv->info, BPF_ANY);

						/* Presumed exception-path until used or freed */
						struct exception_key ek = {
							.ptr_id = hdp->devptr
						};
						struct heap_exception *he =
							bpf_map_lookup_elem(
								&heap_exception_map,
								&zero);
						if (he) {
							__builtin_memset(
								&he->entry, 0,
								sizeof(he->entry));
							he->entry.proc =
								hv->info.proc;
							he->entry.devptr =
								hv->info.devptr;
							he->entry.size =
								hv->info.size;
							he->entry.alloc_ts =
								hv->info.alloc_ts;
							he->entry.pid =
								hv->info.pid;
							bpf_map_update_elem(
								&exception_path_allocs,
								&ek,
								&he->entry,
								BPF_ANY);
						}

					}
				}
			}
		}
	}

	if (gadget_should_discard_data_current())
		return 0;

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
 * Mark a device pointer as "used" in the VRAM tracker.
 * On first use (0->1):
 *   - Add to leaked_allocs (presumed leak until freed)
 *   - Remove from exception_path_allocs (it IS being used)
 */
static __always_inline void mark_devptr_used(__u64 devptr)
{
	if (!devptr)
		return;

	struct vram_alloc_info *info =
		bpf_map_lookup_elem(&vram_tracker, &devptr);
	if (!info)
		return;

	if (!info->used) {
		info->used = 1;

		/* Add to leaked_allocs — will be removed if freed */
		u32 zero = 0;
		struct heap_leaked *hl =
			bpf_map_lookup_elem(&heap_leaked_map, &zero);
		if (hl) {
			__builtin_memset(&hl->entry, 0, sizeof(hl->entry));
			hl->entry.proc = info->proc;
			hl->entry.devptr = info->devptr;
			hl->entry.size = info->size;
			hl->entry.alloc_ts = info->alloc_ts;
			hl->entry.first_use_ts = bpf_ktime_get_ns();
			hl->entry.pid = info->pid;

			struct leaked_key lk = { .ptr_id = devptr };
			bpf_map_update_elem(&leaked_allocs, &lk, &hl->entry,
					    BPF_ANY);
		}

		/* No longer an exception-path alloc — it was used */
		struct exception_key ek = { .ptr_id = devptr };
		bpf_map_delete_elem(&exception_path_allocs, &ek);
	}
}

/* ===== cuMemAlloc_v2 ===== */

SEC("uprobe/libcuda:cuMemAlloc_v2")
int BPF_UPROBE(trace_uprobe_cuMemAlloc_v2, void **dptr, size_t bytesize)
{
	gen_alloc_enter(bytesize);

	u32 tid = (u32)bpf_get_current_pid_tgid();
	struct alloc_scratch scratch = {
		.dptr_user_addr = (__u64)dptr,
		.size = bytesize,
	};
	bpf_map_update_elem(&alloc_scratch_map, &tid, &scratch, BPF_ANY);

	return 0;
}

SEC("uretprobe/libcuda:cuMemAlloc_v2")
int trace_uretprobe_cuMemAlloc_v2(struct pt_regs *ctx)
{
	return gen_alloc_exit_with_vram(ctx, cuMemAlloc, 1);
}

/* cuMemAllocHost_v2 — host memory, no VRAM tracking */
SEC("uprobe/libcuda:cuMemAllocHost_v2")
int BPF_UPROBE(trace_uprobe_cuMemAllocHost_v2, void **pp, size_t bytesize)
{
	return gen_alloc_enter(bytesize);
}

SEC("uretprobe/libcuda:cuMemAllocHost_v2")
int trace_uretprobe_cuMemAllocHost_v2(struct pt_regs *ctx)
{
	return gen_alloc_exit_with_vram(ctx, cuMemAllocHost, 0);
}

/* cuMemAllocManaged — managed memory, track VRAM */
SEC("uprobe/libcuda:cuMemAllocManaged")
int BPF_UPROBE(trace_uprobe_cuMemAllocManaged, void **dptr, size_t bytesize,
	       unsigned int flags)
{
	gen_alloc_enter(bytesize);

	u32 tid = (u32)bpf_get_current_pid_tgid();
	struct alloc_scratch scratch = {
		.dptr_user_addr = (__u64)dptr,
		.size = bytesize,
	};
	bpf_map_update_elem(&alloc_scratch_map, &tid, &scratch, BPF_ANY);

	return 0;
}

SEC("uretprobe/libcuda:cuMemAllocManaged")
int trace_uretprobe_cuMemAllocManaged(struct pt_regs *ctx)
{
	return gen_alloc_exit_with_vram(ctx, cuMemAllocManaged, 1);
}

/* cuMemAllocPitch_v2 — pitched memory, track VRAM */
SEC("uprobe/libcuda:cuMemAllocPitch_v2")
int BPF_UPROBE(trace_uprobe_cuMemAllocPitch_v2, void **dptr, size_t *pPitch,
	       size_t WidthInBytes, size_t Height,
	       unsigned int ElementSizeBytes)
{
	size_t size = WidthInBytes * Height;
	gen_alloc_enter(size);

	u32 tid = (u32)bpf_get_current_pid_tgid();
	struct alloc_scratch scratch = {
		.dptr_user_addr = (__u64)dptr,
		.size = size,
	};
	bpf_map_update_elem(&alloc_scratch_map, &tid, &scratch, BPF_ANY);

	return 0;
}

SEC("uretprobe/libcuda:cuMemAllocPitch_v2")
int trace_uretprobe_cuMemAllocPitch_v2(struct pt_regs *ctx)
{
	return gen_alloc_exit_with_vram(ctx, cuMemAllocPitch, 1);
}

/* ===== VRAM Usage Tracking Probes ===== */

SEC("uprobe/libcuda:cuMemcpyHtoD_v2")
int BPF_UPROBE(trace_uprobe_cuMemcpyHtoD_v2, __u64 dstDevice, void *srcHost,
	       size_t ByteCount)
{
	mark_devptr_used(dstDevice);
	return 0;
}

SEC("uprobe/libcuda:cuMemcpyDtoH_v2")
int BPF_UPROBE(trace_uprobe_cuMemcpyDtoH_v2, void *dstHost, __u64 srcDevice,
	       size_t ByteCount)
{
	mark_devptr_used(srcDevice);
	return 0;
}

SEC("uprobe/libcuda:cuMemcpyDtoD_v2")
int BPF_UPROBE(trace_uprobe_cuMemcpyDtoD_v2, __u64 dstDevice, __u64 srcDevice,
	       size_t ByteCount)
{
	mark_devptr_used(dstDevice);
	mark_devptr_used(srcDevice);
	return 0;
}

SEC("uprobe/libcuda:cuMemcpyHtoDAsync_v2")
int BPF_UPROBE(trace_uprobe_cuMemcpyHtoDAsync_v2, __u64 dstDevice,
	       void *srcHost, size_t ByteCount)
{
	mark_devptr_used(dstDevice);
	return 0;
}

SEC("uprobe/libcuda:cuMemcpyDtoHAsync_v2")
int BPF_UPROBE(trace_uprobe_cuMemcpyDtoHAsync_v2, void *dstHost,
	       __u64 srcDevice, size_t ByteCount)
{
	mark_devptr_used(srcDevice);
	return 0;
}

SEC("uprobe/libcuda:cuMemsetD8_v2")
int BPF_UPROBE(trace_uprobe_cuMemsetD8_v2, __u64 dstDevice)
{
	mark_devptr_used(dstDevice);
	return 0;
}

SEC("uprobe/libcuda:cuMemsetD16_v2")
int BPF_UPROBE(trace_uprobe_cuMemsetD16_v2, __u64 dstDevice)
{
	mark_devptr_used(dstDevice);
	return 0;
}

SEC("uprobe/libcuda:cuMemsetD32_v2")
int BPF_UPROBE(trace_uprobe_cuMemsetD32_v2, __u64 dstDevice)
{
	mark_devptr_used(dstDevice);
	return 0;
}

SEC("uprobe/libcuda:cuLaunchKernel")
int trace_uprobe_cuLaunchKernel(struct pt_regs *ctx)
{
	/*
	 * cuLaunchKernel has 11 args.  kernelParams is #10.
	 * On x86_64 SysV: args 1-6 in registers, 7+ on stack.
	 * At uprobe entry the return address is pushed, so
	 * arg10 is at [rsp + 32].
	 */
	__u64 sp = PT_REGS_SP(ctx);
	void **kernelParams = NULL;

#if defined(__TARGET_ARCH_x86)
	bpf_probe_read_user(&kernelParams, sizeof(kernelParams),
			    (void *)(sp + 32));
#elif defined(__TARGET_ARCH_arm64)
	bpf_probe_read_user(&kernelParams, sizeof(kernelParams),
			    (void *)(sp + 16));
#else
	return 0;
#endif

	if (!kernelParams)
		return 0;

	__u64 param;
	#pragma unroll
	for (int i = 0; i < 8; i++) {
		void *param_ptr = NULL;
		if (bpf_probe_read_user(&param_ptr, sizeof(param_ptr),
					&kernelParams[i]) < 0)
			break;
		if (!param_ptr)
			break;
		if (bpf_probe_read_user(&param, sizeof(param), param_ptr) < 0)
			break;
		mark_devptr_used(param);
	}

	return 0;
}

/* ===== cuMemFree_v2: report unused allocs before removing from tracker ===== */

SEC("uprobe/libcuda:cuMemFree_v2")
int BPF_UPROBE(trace_uprobe_cuMemFree_v2, __u64 dptr)
{
	if (!dptr)
		return 0;

	struct vram_alloc_info *info =
		bpf_map_lookup_elem(&vram_tracker, &dptr);
	if (info) {
		if (!info->used) {
			/* Freed without being accessed — unused */
			struct unused_key uk = { .ptr_id = dptr };
			struct unused_alloc_entry entry = {};
			entry.proc = info->proc;
			entry.devptr = info->devptr;
			entry.size = info->size;
			bpf_map_update_elem(&unused_allocs, &uk, &entry,
					    BPF_ANY);
		}

		/* Freed — not a leak and not an exception-path alloc */
		struct leaked_key lk = { .ptr_id = dptr };
		bpf_map_delete_elem(&leaked_allocs, &lk);

		struct exception_key ek = { .ptr_id = dptr };
		bpf_map_delete_elem(&exception_path_allocs, &ek);

	}
	bpf_map_delete_elem(&vram_tracker, &dptr);
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
