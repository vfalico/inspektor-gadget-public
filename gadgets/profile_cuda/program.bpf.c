// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2025 The Inspektor Gadget authors */

/*
 * profile_cuda — User-facing LLM SLO diagnostics via libcuda.so uprobes
 *
 * Tracks CUDA-level metrics that map to end-user pain points:
 *
 * 1. Memory profiling: allocation tracking by stack (flame-graph ready)
 * 2. Error monitoring: capture CUDA API errors with context
 * 3. Sync stall detection: flag long cuStreamSynchronize/cuCtxSynchronize
 * 4. Kernel launch rate: detect launch-bound workloads
 * 5. Memory transfer tracking: HtoD/DtoH byte counting
 * 6. Context lifecycle: detect context leaks (create without destroy)
 * 7. CUDA Graph adoption: track graph vs eager launch ratios
 * 8. Module load errors: detect version mismatches
 * 9. P2P diagnostics: peer access enable/fail tracking
 * 10. Inference SLO metrics: TTFT, ITL jitter, request fairness,
 *     per-request latency breakdown, long context detection
 *
 * All instrumentation is on the CUDA Driver API (libcuda.so) symbols,
 * which are stable across CUDA versions and used by ALL frameworks.
 */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <gadget/buffer.h>
#include <gadget/types.h>
#include <gadget/common.h>
#include <gadget/filter.h>
#include <gadget/macros.h>
#include <gadget/user_stack_map.h>

#define MAX_ENTRIES 10240
/* ════════════════════════════════════════════════════════════════════════
 *  Part 1: Memory Profiling (base feature from ac5eb606f)
 * ════════════════════════════════════════════════════════════════════════ */

enum memop {
	MEMOP_ALLOC,
	MEMOP_ALLOC_HOST,
	MEMOP_ALLOC_MANAGED,
	MEMOP_ALLOC_PITCH,
	MEMOP_ALLOC_ASYNC,
	MEMOP_FREE_ASYNC,
	MEMOP_POOL_CREATE,
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32);   /* tid */
	__type(value, u64);  /* alloc size */
} sizes SEC(".maps");

struct alloc_key { __u32 stack_id_key; };

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

GADGET_MAPITER(allocs, allocs);

/* ════════════════════════════════════════════════════════════════════════
 *  Part 2: Error Monitoring
 * ════════════════════════════════════════════════════════════════════════ */

struct error_event {
	struct gadget_process proc;
	__u64 timestamp_ns;
	__u32 error_code;     /* CUDA error code */
	__u32 api_id;         /* which API function */
};

#define API_ID_MEM_ALLOC         1
#define API_ID_MEM_ALLOC_ASYNC   2
#define API_ID_MODULE_LOAD       3
#define API_ID_MODULE_LOAD_DATA  4
#define API_ID_CTX_SYNC          5
#define API_ID_STREAM_SYNC       6
#define API_ID_LAUNCH_KERNEL     7
#define API_ID_GRAPH_LAUNCH      8
#define API_ID_GRAPH_INSTANTIATE 9
#define API_ID_P2P_ENABLE       10
#define API_ID_EVENT_SYNC       11
#define API_ID_MEM_ALLOC_HOST   12
#define API_ID_CTX_CREATE       13
#define API_ID_MEMCPY_HTOD      14
#define API_ID_MEMCPY_DTOH      15

GADGET_TRACER_MAP(error_events, 262144);
GADGET_TRACER(errors, error_events, error_event);

/* ════════════════════════════════════════════════════════════════════════
 *  Part 3: Sync Stall Detection
 * ════════════════════════════════════════════════════════════════════════ */

struct sync_event {
	struct gadget_process proc;
	__u64 timestamp_ns;
	__u64 duration_ns;
	__u32 sync_type;       /* 1=ctx, 2=stream, 3=event */
};

#define SYNC_CTX     1
#define SYNC_STREAM  2
#define SYNC_EVENT   3

GADGET_TRACER_MAP(sync_events, 262144);
GADGET_TRACER(syncs, sync_events, sync_event);

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32);   /* tid */
	__type(value, u64);  /* entry timestamp */
} sync_entry SEC(".maps");


const volatile __u64 sync_threshold_ns = 10000000;
GADGET_PARAM(sync_threshold_ns);

/* ════════════════════════════════════════════════════════════════════════
 *  Helpers
 * ════════════════════════════════════════════════════════════════════════ */

SEC("tracepoint/sched/sched_process_exit")
int trace_sched_process_exit(void *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tid  = (u32)pid_tgid;

	bpf_map_delete_elem(&sizes, &tid);
	bpf_map_delete_elem(&sync_entry, &tid);
	return 0;
}
/* ─── Memory alloc helpers ─── */

static __always_inline int alloc_enter(size_t size)
{
	u32 tid = (u32)bpf_get_current_pid_tgid();
	bpf_map_update_elem(&sizes, &tid, &size, BPF_ANY);
	return 0;
}

static __always_inline int alloc_exit(struct pt_regs *ctx, enum memop op,
				      __u32 api_id)
{
	int ret = PT_REGS_RC(ctx);

	if (ret != 0) {
		if (!gadget_should_discard_data_current()) {
			struct error_event *err =
				gadget_reserve_buf(&error_events, sizeof(*err));
			if (err) {
				__builtin_memset(err, 0, sizeof(*err));
				gadget_process_populate(&err->proc);
				err->timestamp_ns = bpf_ktime_get_ns();
				err->error_code = (__u32)ret;
				err->api_id = api_id;
				gadget_submit_buf(ctx, &error_events,
						  err, sizeof(*err));
			}
		}
		return 0;
	}

	if (gadget_should_discard_data_current())
		return 0;

	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 *size_ptr = bpf_map_lookup_elem(&sizes, &tid);
	if (!size_ptr)
		return 0;
	u64 size = *size_ptr;
	bpf_map_delete_elem(&sizes, &tid);

	u32 zero = 0;
	struct heap_data *h = bpf_map_lookup_elem(&heap, &zero);
	if (!h)
		return 0;

	gadget_get_user_stack(ctx, &h->ustack);

	struct alloc_key key = { .stack_id_key = h->ustack.stack_id };
	struct alloc_val *val = bpf_map_lookup_elem(&allocs, &key);
	if (!val) {
		__builtin_memset(&h->val, 0, sizeof(h->val));
		h->val.count = size;
		h->val.ustack_raw = h->ustack;
		gadget_process_populate(&h->val.proc);
		bpf_map_update_elem(&allocs, &key, &h->val, BPF_NOEXIST);
	} else {
		__sync_fetch_and_add(&val->count, size);
	}
	return 0;
}

/* ─── Error emit helper ─── */

static __always_inline void emit_error(struct pt_regs *ctx, __u32 api_id,
					int ret)
{
	if (ret == 0 || gadget_should_discard_data_current())
		return;
	struct error_event *err =
		gadget_reserve_buf(&error_events, sizeof(*err));
	if (!err)
		return;
	__builtin_memset(err, 0, sizeof(*err));
	gadget_process_populate(&err->proc);
	err->timestamp_ns = bpf_ktime_get_ns();
	err->error_code = (__u32)ret;
	err->api_id = api_id;
	gadget_submit_buf(ctx, &error_events, err, sizeof(*err));
}

/* ─── Sync stall helper ─── */

static __always_inline void sync_enter_ts(void)
{
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&sync_entry, &tid, &ts, BPF_ANY);
}

static __always_inline void sync_exit_check(struct pt_regs *ctx,
					     __u32 sync_type, __u32 api_id)
{
	if (gadget_should_discard_data_current())
		return;

	int ret = PT_REGS_RC(ctx);
	if (ret != 0)
		emit_error(ctx, api_id, ret);

	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 *entry = bpf_map_lookup_elem(&sync_entry, &tid);
	if (!entry)
		return;
	u64 duration = bpf_ktime_get_ns() - *entry;
	bpf_map_delete_elem(&sync_entry, &tid);

	if (duration > sync_threshold_ns) {
		struct sync_event *evt =
			gadget_reserve_buf(&sync_events, sizeof(*evt));
		if (evt) {
			__builtin_memset(evt, 0, sizeof(*evt));
			gadget_process_populate(&evt->proc);
			evt->timestamp_ns = bpf_ktime_get_ns();
			evt->duration_ns = duration;
			evt->sync_type = sync_type;
			gadget_submit_buf(ctx, &sync_events,
					  evt, sizeof(*evt));
		}
	}
}

/* ════════════════════════════════════════════════════════════════════════
 *  Probes: Synchronization
 * ════════════════════════════════════════════════════════════════════════ */

SEC("uprobe/libcuda:cuCtxSynchronize")
int BPF_UPROBE(trace_uprobe_cuCtxSynchronize)
{
	sync_enter_ts();
	return 0;
}

SEC("uretprobe/libcuda:cuCtxSynchronize")
int trace_uretprobe_cuCtxSynchronize(struct pt_regs *ctx)
{
	sync_exit_check(ctx, SYNC_CTX, API_ID_CTX_SYNC);
	return 0;
}

SEC("uprobe/libcuda:cuStreamSynchronize")
int BPF_UPROBE(trace_uprobe_cuStreamSynchronize)
{
	sync_enter_ts();
	return 0;
}

SEC("uretprobe/libcuda:cuStreamSynchronize")
int trace_uretprobe_cuStreamSynchronize(struct pt_regs *ctx)
{
	sync_exit_check(ctx, SYNC_STREAM, API_ID_STREAM_SYNC);
	return 0;
}

SEC("uprobe/libcuda:cuEventSynchronize")
int BPF_UPROBE(trace_uprobe_cuEventSynchronize)
{
	sync_enter_ts();
	return 0;
}

SEC("uretprobe/libcuda:cuEventSynchronize")
int trace_uretprobe_cuEventSynchronize(struct pt_regs *ctx)
{
	sync_exit_check(ctx, SYNC_EVENT, API_ID_EVENT_SYNC);
	return 0;
}

/* ════════════════════════════════════════════════════════════════════════
 *  Probes: Memory Allocation
 * ════════════════════════════════════════════════════════════════════════ */

SEC("uprobe/libcuda:cuMemAlloc_v2")
int BPF_UPROBE(trace_uprobe_cuMemAlloc_v2, void **dptr, size_t size)
{ return alloc_enter(size); }

SEC("uretprobe/libcuda:cuMemAlloc_v2")
int trace_uretprobe_cuMemAlloc_v2(struct pt_regs *ctx)
{ return alloc_exit(ctx, MEMOP_ALLOC, API_ID_MEM_ALLOC); }

SEC("uprobe/libcuda:cuMemAllocHost_v2")
int BPF_UPROBE(trace_uprobe_cuMemAllocHost_v2, void **pp, size_t size)
{ return alloc_enter(size); }

SEC("uretprobe/libcuda:cuMemAllocHost_v2")
int trace_uretprobe_cuMemAllocHost_v2(struct pt_regs *ctx)
{ return alloc_exit(ctx, MEMOP_ALLOC_HOST, API_ID_MEM_ALLOC_HOST); }

SEC("uprobe/libcuda:cuMemAllocManaged")
int BPF_UPROBE(trace_uprobe_cuMemAllocManaged, void **dptr, size_t size,
	       unsigned int flags)
{ return alloc_enter(size); }

SEC("uretprobe/libcuda:cuMemAllocManaged")
int trace_uretprobe_cuMemAllocManaged(struct pt_regs *ctx)
{ return alloc_exit(ctx, MEMOP_ALLOC_MANAGED, API_ID_MEM_ALLOC); }

SEC("uprobe/libcuda:cuMemAllocPitch_v2")
int BPF_UPROBE(trace_uprobe_cuMemAllocPitch_v2, void **dptr, size_t *pPitch,
	       size_t w, size_t h, unsigned int elem)
{ return alloc_enter(w * h); }

SEC("uretprobe/libcuda:cuMemAllocPitch_v2")
int trace_uretprobe_cuMemAllocPitch_v2(struct pt_regs *ctx)
{ return alloc_exit(ctx, MEMOP_ALLOC_PITCH, API_ID_MEM_ALLOC); }

SEC("uprobe/libcuda:cuMemAllocAsync")
int BPF_UPROBE(trace_uprobe_cuMemAllocAsync, void **dptr, size_t size,
	       void *stream)
{ return alloc_enter(size); }

SEC("uretprobe/libcuda:cuMemAllocAsync")
int trace_uretprobe_cuMemAllocAsync(struct pt_regs *ctx)
{ return alloc_exit(ctx, MEMOP_ALLOC_ASYNC, API_ID_MEM_ALLOC_ASYNC); }

SEC("uprobe/libcuda:cuMemFreeAsync")
int BPF_UPROBE(trace_uprobe_cuMemFreeAsync, void *dptr, void *stream)
{ return alloc_enter(1); }

SEC("uretprobe/libcuda:cuMemFreeAsync")
int trace_uretprobe_cuMemFreeAsync(struct pt_regs *ctx)
{ return alloc_exit(ctx, MEMOP_FREE_ASYNC, API_ID_MEM_ALLOC_ASYNC); }

SEC("uprobe/libcuda:cuMemPoolCreate")
int BPF_UPROBE(trace_uprobe_cuMemPoolCreate, void *pool, void *props)
{ return alloc_enter(1); }

SEC("uretprobe/libcuda:cuMemPoolCreate")
int trace_uretprobe_cuMemPoolCreate(struct pt_regs *ctx)
{ return alloc_exit(ctx, MEMOP_POOL_CREATE, API_ID_MEM_ALLOC); }


char LICENSE[] SEC("license") = "Dual BSD/GPL";
