// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2026 The Inspektor Gadget authors */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <gadget/buffer.h>
#include <gadget/common.h>
#include <gadget/filter.h>
#include <gadget/macros.h>
#include <gadget/types.h>

#define MAX_PENDING_CALLS 8192
#define MAX_STAT_ROWS 4096
#define CUDA_DEVICE_UNKNOWN (-1)

enum cuda_operation {
	CUDA_OP_LAUNCH_KERNEL,
	CUDA_OP_LAUNCH_KERNEL_EX,
	CUDA_OP_GRAPH_LAUNCH,
	CUDA_OP_MEMCPY_DTOH,
	CUDA_OP_MEMCPY_DTOH_ASYNC,
	CUDA_OP_MEMCPY_HTOD,
	CUDA_OP_MEMCPY_HTOD_ASYNC,
	CUDA_OP_MEMCPY_DTOD,
	CUDA_OP_MEMCPY_DTOD_ASYNC,
	CUDA_OP_MEM_ALLOC,
	CUDA_OP_MEM_ALLOC_ASYNC,
	CUDA_OP_MEM_FREE,
	CUDA_OP_MEM_FREE_ASYNC,
	CUDA_OP_STREAM_SYNCHRONIZE,
	CUDA_OP_CONTEXT_SYNCHRONIZE,
	CUDA_OP_EVENT_SYNCHRONIZE,
	CUDA_OP_CONTEXT_GET_DEVICE,
	CUDA_OP_MAX,
};

enum cuda_copy_direction {
	CUDA_COPY_NONE,
	CUDA_COPY_DTOH,
	CUDA_COPY_HTOD,
	CUDA_COPY_DTOD,
};

struct call_key {
	__u64 pid_tgid;
	enum cuda_operation operation;
};

struct pending_call {
	gadget_timestamp start_ns;
	__u64 bytes;
	__u64 stream;
	__u64 function;
	__u64 pointer;
	__u64 output_pointer;
	__u32 grid_x;
	__u32 grid_y;
	__u32 grid_z;
	__u32 block_x;
	__u32 block_y;
	__u32 block_z;
	__u32 shared_mem_bytes;
	enum cuda_operation operation;
	enum cuda_copy_direction copy_direction;
};

struct event {
	gadget_timestamp timestamp_raw;
	struct gadget_process proc;
	gadget_duration duration_raw;
	__u64 bytes;
	__u64 stream;
	__u64 function;
	__u64 pointer;
	__u32 grid_x;
	__u32 grid_y;
	__u32 grid_z;
	__u32 block_x;
	__u32 block_y;
	__u32 block_z;
	__u32 shared_mem_bytes;
	__u8 has_stream;
	__u8 has_device;
	__u8 has_function;
	__u8 has_pointer;
	__s32 device;
	__s32 result;
	enum cuda_operation operation_raw;
	enum cuda_copy_direction copy_direction_raw;
};

struct stat_key {
	enum cuda_operation operation_raw;
};

struct cuda_stat {
	gadget_counter__u64 calls;
	gadget_counter__u64 errors;
	gadget_counter__u64 requested_bytes;
	gadget_counter__u64 duration_ns;
	gadget_counter__u64 unmatched_returns;
	gadget_counter__u64 reserve_failures;
	gadget_counter__u64 pending_update_failures;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, MAX_PENDING_CALLS);
	__type(key, struct call_key);
	__type(value, struct pending_call);
} pending_calls SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_STAT_ROWS);
	__type(key, struct stat_key);
	__type(value, struct cuda_stat);
} cuda_stats SEC(".maps");
GADGET_MAPITER(cuda_stats, cuda_stats);

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, __s32);
} process_devices SEC(".maps");

GADGET_TRACER_MAP(events, 1024 * 1024);
GADGET_TRACER(cuda_calls, events, event);

static __always_inline struct cuda_stat *get_stat(enum cuda_operation op)
{
	struct stat_key key = {
		.operation_raw = op,
	};
	struct cuda_stat *s = bpf_map_lookup_elem(&cuda_stats, &key);
	if (!s) {
		struct cuda_stat zero = {};
		bpf_map_update_elem(&cuda_stats, &key, &zero, BPF_NOEXIST);
		s = bpf_map_lookup_elem(&cuda_stats, &key);
	}
	return s;
}

static __always_inline int call_enter(struct pending_call *pending)
{
	struct call_key key = {
		.pid_tgid = bpf_get_current_pid_tgid(),
		.operation = pending->operation,
	};
	int rc;

	if (gadget_should_discard_data_current())
		return 0;
	pending->start_ns = bpf_ktime_get_ns();
	rc = bpf_map_update_elem(&pending_calls, &key, pending, BPF_ANY);
	if (rc) {
		struct cuda_stat *s = get_stat(pending->operation);
		if (s)
			__sync_fetch_and_add(&s->pending_update_failures, 1);
	}
	return 0;
}

static __always_inline int call_exit(struct pt_regs *ctx,
				     enum cuda_operation expected)
{
	struct call_key key = {
		.pid_tgid = bpf_get_current_pid_tgid(),
		.operation = expected,
	};
	struct pending_call *stored;
	struct pending_call call;
	struct cuda_stat *s;
	struct event *event;
	__u64 now, timestamp_boot, duration;
	__s32 result = (__s32)PT_REGS_RC(ctx);
	__u32 pid = (__u32)(key.pid_tgid >> 32);
	__s32 device = CUDA_DEVICE_UNKNOWN;

	stored = bpf_map_lookup_elem(&pending_calls, &key);
	if (!stored || stored->operation != expected) {
		s = get_stat(expected);
		if (s)
			__sync_fetch_and_add(&s->unmatched_returns, 1);
		return 0;
	}
	call = *stored;
	bpf_map_delete_elem(&pending_calls, &key);
	now = bpf_ktime_get_ns();
	timestamp_boot = bpf_ktime_get_boot_ns();
	duration = now - call.start_ns;

	if ((expected == CUDA_OP_MEM_ALLOC || expected == CUDA_OP_MEM_ALLOC_ASYNC) &&
	    result == 0 && call.output_pointer)
		bpf_probe_read_user(&call.pointer, sizeof(call.pointer),
				    (void *)call.output_pointer);

	if (expected == CUDA_OP_CONTEXT_GET_DEVICE && result == 0 &&
	    call.output_pointer) {
		if (bpf_probe_read_user(&device, sizeof(device),
					(void *)call.output_pointer) == 0)
			bpf_map_update_elem(&process_devices, &pid, &device, BPF_ANY);
	} else {
		__s32 *cached = bpf_map_lookup_elem(&process_devices, &pid);
		if (cached)
			device = *cached;
	}

	s = get_stat(expected);
	if (s) {
		__sync_fetch_and_add(&s->calls, 1);
		__sync_fetch_and_add(&s->requested_bytes, call.bytes);
		__sync_fetch_and_add(&s->duration_ns, duration);
		if (result)
			__sync_fetch_and_add(&s->errors, 1);
	}

	event = gadget_reserve_buf(&events, sizeof(*event));
	if (!event) {
		if (s)
			__sync_fetch_and_add(&s->reserve_failures, 1);
		return 0;
	}
	__builtin_memset(event, 0, sizeof(*event));
	event->timestamp_raw = timestamp_boot;
	event->duration_raw = duration;
	event->bytes = call.bytes;
	event->stream = call.stream;
	event->function = call.function;
	event->pointer = call.pointer;
	event->grid_x = call.grid_x;
	event->grid_y = call.grid_y;
	event->grid_z = call.grid_z;
	event->block_x = call.block_x;
	event->block_y = call.block_y;
	event->block_z = call.block_z;
	event->shared_mem_bytes = call.shared_mem_bytes;
	event->has_stream = call.stream != 0;
	event->has_device = device != CUDA_DEVICE_UNKNOWN;
	event->has_function = call.function != 0;
	event->has_pointer = call.pointer != 0;
	event->device = device;
	event->result = result;
	event->operation_raw = call.operation;
	event->copy_direction_raw = call.copy_direction;
	gadget_process_populate(&event->proc);
	gadget_submit_buf(ctx, &events, event, sizeof(*event));
	return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int trace_sched_process_exit(void *ctx)
{
	struct call_key key = { .pid_tgid = bpf_get_current_pid_tgid() };
	__u32 pid = (__u32)(key.pid_tgid >> 32);
#pragma unroll
	for (int operation = 0; operation < CUDA_OP_MAX; operation++) {
		key.operation = operation;
		bpf_map_delete_elem(&pending_calls, &key);
	}
	bpf_map_delete_elem(&process_devices, &pid);
	return 0;
}

#define PROBE_SIMPLE(symbol, suffix, op)                           \
	SEC("uprobe/libcuda:" #symbol) int BPF_UPROBE(cuda_##suffix##_enter) \
	{ struct pending_call p = {.operation = op}; return call_enter(&p); } \
	SEC("uretprobe/libcuda:" #symbol) int cuda_##suffix##_exit(struct pt_regs *ctx) \
	{ return call_exit(ctx, op); }

#define PROBE_COPY_SYNC(symbol, suffix, op, direction) \
	SEC("uprobe/libcuda:" #symbol) int BPF_UPROBE(cuda_##suffix##_enter, \
		__u64 first, __u64 second, size_t bytes) \
	{ struct pending_call p = {.operation = op, .copy_direction = direction, \
		.bytes = bytes}; return call_enter(&p); } \
	SEC("uretprobe/libcuda:" #symbol) int cuda_##suffix##_exit(struct pt_regs *ctx) \
	{ return call_exit(ctx, op); }

#define PROBE_COPY_ASYNC(symbol, suffix, op, direction) \
	SEC("uprobe/libcuda:" #symbol) int BPF_UPROBE(cuda_##suffix##_enter, \
		__u64 first, __u64 second, size_t bytes, void *stream) \
	{ struct pending_call p = {.operation = op, .copy_direction = direction, \
		.bytes = bytes, .stream = (__u64)stream}; return call_enter(&p); } \
	SEC("uretprobe/libcuda:" #symbol) int cuda_##suffix##_exit(struct pt_regs *ctx) \
	{ return call_exit(ctx, op); }

#define PROBE_ALLOC_SYNC(symbol, suffix, op) \
	SEC("uprobe/libcuda:" #symbol) int BPF_UPROBE(cuda_##suffix##_enter, \
		__u64 *out, size_t bytes) \
	{ struct pending_call p = {.operation = op, .bytes = bytes, \
		.output_pointer = (__u64)out}; return call_enter(&p); } \
	SEC("uretprobe/libcuda:" #symbol) int cuda_##suffix##_exit(struct pt_regs *ctx) \
	{ return call_exit(ctx, op); }

#define PROBE_ALLOC_ASYNC(symbol, suffix, op) \
	SEC("uprobe/libcuda:" #symbol) int BPF_UPROBE(cuda_##suffix##_enter, \
		__u64 *out, size_t bytes, void *stream) \
	{ struct pending_call p = {.operation = op, .bytes = bytes, \
		.output_pointer = (__u64)out, .stream = (__u64)stream}; return call_enter(&p); } \
	SEC("uretprobe/libcuda:" #symbol) int cuda_##suffix##_exit(struct pt_regs *ctx) \
	{ return call_exit(ctx, op); }

#define PROBE_FREE_SYNC(symbol, suffix, op) \
	SEC("uprobe/libcuda:" #symbol) int BPF_UPROBE(cuda_##suffix##_enter, __u64 ptr) \
	{ struct pending_call p = {.operation = op, .pointer = ptr}; return call_enter(&p); } \
	SEC("uretprobe/libcuda:" #symbol) int cuda_##suffix##_exit(struct pt_regs *ctx) \
	{ return call_exit(ctx, op); }

#define PROBE_FREE_ASYNC(symbol, suffix, op) \
	SEC("uprobe/libcuda:" #symbol) int BPF_UPROBE(cuda_##suffix##_enter, \
		__u64 ptr, void *stream) \
	{ struct pending_call p = {.operation = op, .pointer = ptr, \
		.stream = (__u64)stream}; return call_enter(&p); } \
	SEC("uretprobe/libcuda:" #symbol) int cuda_##suffix##_exit(struct pt_regs *ctx) \
	{ return call_exit(ctx, op); }

/*
 * cuLaunchKernel has nine arguments. libbpf's BPF_UPROBE typed wrapper only
 * expands eight, so decode the SysV x86-64 ABI explicitly: arguments 1-6 are
 * registers, the return address is at SP, and arguments 7-9 follow it.
 * The local OCI artifact is linux/amd64; packaging rejects other platforms.
 */
static __always_inline int launch_kernel_enter(struct pt_regs *ctx)
{
	__u64 sp = PT_REGS_SP(ctx);
	__u64 bz = 0, shared = 0, stream = 0;
	struct pending_call p = {
		.operation = CUDA_OP_LAUNCH_KERNEL,
		.function = (__u64)PT_REGS_PARM1(ctx),
		.grid_x = (__u32)PT_REGS_PARM2(ctx),
		.grid_y = (__u32)PT_REGS_PARM3(ctx),
		.grid_z = (__u32)PT_REGS_PARM4(ctx),
		.block_x = (__u32)PT_REGS_PARM5(ctx),
		.block_y = (__u32)PT_REGS_PARM6(ctx),
	};
	if (bpf_probe_read_user(&bz, sizeof(bz), (void *)(sp + 8)) ||
	    bpf_probe_read_user(&shared, sizeof(shared), (void *)(sp + 16)) ||
	    bpf_probe_read_user(&stream, sizeof(stream), (void *)(sp + 24)))
		return 0;
	p.block_z = (__u32)bz;
	p.shared_mem_bytes = (__u32)shared;
	p.stream = stream;
	return call_enter(&p);
}

SEC("uprobe/libcuda:cuLaunchKernel")
int cuda_launch_kernel_enter(struct pt_regs *ctx)
{ return launch_kernel_enter(ctx); }
SEC("uretprobe/libcuda:cuLaunchKernel")
int cuda_launch_kernel_exit(struct pt_regs *ctx)
{ return call_exit(ctx, CUDA_OP_LAUNCH_KERNEL); }

SEC("uprobe/libcuda:cuLaunchKernel_ptsz")
int cuda_launch_kernel_ptsz_enter(struct pt_regs *ctx)
{ return launch_kernel_enter(ctx); }
SEC("uretprobe/libcuda:cuLaunchKernel_ptsz")
int cuda_launch_kernel_ptsz_exit(struct pt_regs *ctx)
{ return call_exit(ctx, CUDA_OP_LAUNCH_KERNEL); }

PROBE_SIMPLE(cuLaunchKernelEx, launch_kernel_ex, CUDA_OP_LAUNCH_KERNEL_EX)
PROBE_SIMPLE(cuLaunchKernelEx_ptsz, launch_kernel_ex_ptsz, CUDA_OP_LAUNCH_KERNEL_EX)
#define PROBE_GRAPH(symbol, suffix) \
	SEC("uprobe/libcuda:" #symbol) int BPF_UPROBE(cuda_##suffix##_enter, \
		void *graph_exec, void *stream) \
	{ struct pending_call p = {.operation = CUDA_OP_GRAPH_LAUNCH, \
		.function = (__u64)graph_exec, .stream = (__u64)stream}; return call_enter(&p); } \
	SEC("uretprobe/libcuda:" #symbol) int cuda_##suffix##_exit(struct pt_regs *ctx) \
	{ return call_exit(ctx, CUDA_OP_GRAPH_LAUNCH); }
PROBE_GRAPH(cuGraphLaunch, graph_launch)
PROBE_GRAPH(cuGraphLaunch_ptsz, graph_launch_ptsz)

PROBE_COPY_SYNC(cuMemcpyDtoH_v2, memcpy_dtoh, CUDA_OP_MEMCPY_DTOH, CUDA_COPY_DTOH)
PROBE_COPY_SYNC(cuMemcpyDtoH_v2_ptds, memcpy_dtoh_ptds, CUDA_OP_MEMCPY_DTOH, CUDA_COPY_DTOH)
PROBE_COPY_ASYNC(cuMemcpyDtoHAsync_v2, memcpy_dtoh_async, CUDA_OP_MEMCPY_DTOH_ASYNC, CUDA_COPY_DTOH)
PROBE_COPY_ASYNC(cuMemcpyDtoHAsync_v2_ptsz, memcpy_dtoh_async_ptsz, CUDA_OP_MEMCPY_DTOH_ASYNC, CUDA_COPY_DTOH)
PROBE_COPY_SYNC(cuMemcpyHtoD_v2, memcpy_htod, CUDA_OP_MEMCPY_HTOD, CUDA_COPY_HTOD)
PROBE_COPY_SYNC(cuMemcpyHtoD_v2_ptds, memcpy_htod_ptds, CUDA_OP_MEMCPY_HTOD, CUDA_COPY_HTOD)
PROBE_COPY_ASYNC(cuMemcpyHtoDAsync_v2, memcpy_htod_async, CUDA_OP_MEMCPY_HTOD_ASYNC, CUDA_COPY_HTOD)
PROBE_COPY_ASYNC(cuMemcpyHtoDAsync_v2_ptsz, memcpy_htod_async_ptsz, CUDA_OP_MEMCPY_HTOD_ASYNC, CUDA_COPY_HTOD)
PROBE_COPY_SYNC(cuMemcpyDtoD_v2, memcpy_dtod, CUDA_OP_MEMCPY_DTOD, CUDA_COPY_DTOD)
PROBE_COPY_SYNC(cuMemcpyDtoD_v2_ptds, memcpy_dtod_ptds, CUDA_OP_MEMCPY_DTOD, CUDA_COPY_DTOD)
PROBE_COPY_ASYNC(cuMemcpyDtoDAsync_v2, memcpy_dtod_async, CUDA_OP_MEMCPY_DTOD_ASYNC, CUDA_COPY_DTOD)
PROBE_COPY_ASYNC(cuMemcpyDtoDAsync_v2_ptsz, memcpy_dtod_async_ptsz, CUDA_OP_MEMCPY_DTOD_ASYNC, CUDA_COPY_DTOD)

PROBE_ALLOC_SYNC(cuMemAlloc_v2, mem_alloc, CUDA_OP_MEM_ALLOC)
PROBE_ALLOC_ASYNC(cuMemAllocAsync, mem_alloc_async, CUDA_OP_MEM_ALLOC_ASYNC)
PROBE_ALLOC_ASYNC(cuMemAllocAsync_ptsz, mem_alloc_async_ptsz, CUDA_OP_MEM_ALLOC_ASYNC)
PROBE_FREE_SYNC(cuMemFree_v2, mem_free, CUDA_OP_MEM_FREE)
PROBE_FREE_ASYNC(cuMemFreeAsync, mem_free_async, CUDA_OP_MEM_FREE_ASYNC)
PROBE_FREE_ASYNC(cuMemFreeAsync_ptsz, mem_free_async_ptsz, CUDA_OP_MEM_FREE_ASYNC)

PROBE_SIMPLE(cuStreamSynchronize, stream_synchronize, CUDA_OP_STREAM_SYNCHRONIZE)
PROBE_SIMPLE(cuStreamSynchronize_ptsz, stream_synchronize_ptsz, CUDA_OP_STREAM_SYNCHRONIZE)
PROBE_SIMPLE(cuCtxSynchronize, context_synchronize, CUDA_OP_CONTEXT_SYNCHRONIZE)
PROBE_SIMPLE(cuEventSynchronize, event_synchronize, CUDA_OP_EVENT_SYNCHRONIZE)

SEC("uprobe/libcuda:cuCtxGetDevice")
int BPF_UPROBE(cuda_ctx_get_device_enter, int *device)
{
	struct pending_call p = {.operation = CUDA_OP_CONTEXT_GET_DEVICE,
		.output_pointer = (__u64)device};
	return call_enter(&p);
}
SEC("uretprobe/libcuda:cuCtxGetDevice")
int cuda_ctx_get_device_exit(struct pt_regs *ctx)
{ return call_exit(ctx, CUDA_OP_CONTEXT_GET_DEVICE); }

char LICENSE[] SEC("license") = "Dual BSD/GPL";
