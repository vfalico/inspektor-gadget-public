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

/* ════════════════════════════════════════════════════════════════════════
 *  Part 4: Kernel Launch Tracking
 * ════════════════════════════════════════════════════════════════════════ */

struct launch_event {
	struct gadget_process proc;
	__u64 timestamp_ns;
	__u32 launch_type;    /* 1=kernel, 2=graph */
};

#define LAUNCH_KERNEL 1
#define LAUNCH_GRAPH  2

GADGET_TRACER_MAP(launch_events, 1048576);
GADGET_TRACER(launches, launch_events, launch_event);

/* ════════════════════════════════════════════════════════════════════════
 *  Part 5: Memory Transfer Tracking
 * ════════════════════════════════════════════════════════════════════════ */

struct memcpy_event {
	struct gadget_process proc;
	__u64 timestamp_ns;
	__u64 size_bytes;
	__u32 direction;       /* 1=HtoD, 2=DtoH, 3=DtoD, 4=Peer */
	__u32 is_async;
};

#define DIR_HTOD  1
#define DIR_DTOH  2
#define DIR_DTOD  3
#define DIR_PEER  4

GADGET_TRACER_MAP(memcpy_events, 524288);
GADGET_TRACER(memcpys, memcpy_events, memcpy_event);

/* ════════════════════════════════════════════════════════════════════════
 *  Part 6: Context Lifecycle
 * ════════════════════════════════════════════════════════════════════════ */

struct ctx_event {
	struct gadget_process proc;
	__u64 timestamp_ns;
	__u32 event_type;      /* 1=create, 2=destroy, 3=set_current */
};

#define CTX_CREATE  1
#define CTX_DESTROY 2
#define CTX_SET     3

GADGET_TRACER_MAP(ctx_events, 262144);
GADGET_TRACER(contexts, ctx_events, ctx_event);

/* ════════════════════════════════════════════════════════════════════════
 *  Part 7: Inference SLO Metrics (TTFT / Token / Request / SLO)
 * ════════════════════════════════════════════════════════════════════════ */

#define STACK_AUTO      0
#define STACK_LLAMACPP  1
#define STACK_VLLM      2
#define STACK_TGI       3
#define STACK_TRTLLM    4
#define STACK_HF_SDPA   5

enum phase {
	PHASE_IDLE    = 0,
	PHASE_PREFILL = 1,
	PHASE_DECODE  = 2,
};

struct infer_state {
	enum phase phase;
	__u64 prefill_start_ns;
	__u64 last_kernel_ns;
	__u64 first_token_ns;
	__u64 last_token_ns;
	__u32 prefill_kernels;
	__u32 decode_tokens;
	__u32 detected_stack;
	__u32 request_count;
	__u32 graph_launches;
	__u32 event_syncs;
	__u32 stream_syncs;
	__u32 memcpy_asyncs;
	__u32 dtoh_asyncs;
	__u32 kernel_launches;
	__u32 req_event_syncs;
	__u32 req_dtoh_asyncs;
	/* SLO: streaming smoothness tracking */
	__u64 itl_max_ns;        /* max inter-token latency in request */
	__u64 itl_min_ns;        /* min inter-token latency in request */
	__u64 itl_sum_ns;        /* sum of ITL for mean calculation */
	__u64 itl_sum_sq_ns;     /* sum of squared ITL / 1000 for variance */
	/* SLO: long-context tracking */
	__u32 is_long_context;   /* 1 if prefill_kernels > threshold */
};

struct ttft_event {
	struct gadget_process proc;
	__u64 ttft_ns;
	__u32 prefill_kernels;
	__u64 prefill_start;
	__u64 prefill_end;
	__u32 detected_stack;
};

struct token_event {
	struct gadget_process proc;
	__u64 timestamp_ns;
	__u64 inter_token_ns;
	__u32 token_index;
	__u32 detected_stack;
};

struct request_event {
	struct gadget_process proc;
	__u64 e2e_latency_ns;
	__u64 ttft_ns;
	__u64 decode_duration_ns;
	__u32 total_tokens;
	__u32 detected_stack;
	/* SLO: streaming smoothness */
	__u64 itl_max_ns;        /* worst ITL spike */
	__u64 itl_min_ns;        /* best ITL */
	__u64 itl_avg_ns;        /* mean ITL */
	__u64 itl_jitter_ns;     /* max - min ITL (simple jitter) */
	/* SLO: context size indicator */
	__u32 is_long_context;   /* 1 if input was detected as long */
};

/* SLO: long context alert event */
struct long_ctx_event {
	struct gadget_process proc;
	__u64 timestamp_ns;
	__u32 prefill_kernels;
	__u64 estimated_ttft_ns; /* current elapsed since prefill start */
};

GADGET_TRACER_MAP(long_ctx_events, 262144);
GADGET_TRACER(long_ctx_alerts, long_ctx_events, long_ctx_event);

/* ─── Parameters ─── */

const volatile __u64 gap_threshold_ns = 200000;
GADGET_PARAM(gap_threshold_ns);

const volatile __u32 min_prefill_kernels = 10;
GADGET_PARAM(min_prefill_kernels);

const volatile __u64 cooldown_ns = 100000000;
GADGET_PARAM(cooldown_ns);

const volatile __u32 stack_hint = 0;
GADGET_PARAM(stack_hint);

const volatile __u64 sync_threshold_ns = 10000000;
GADGET_PARAM(sync_threshold_ns);

/* SLO: long context alert threshold (prefill kernels) */
const volatile __u32 long_ctx_kernels = 500;
GADGET_PARAM(long_ctx_kernels);

/* ─── Inference state map ─── */

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u32);   /* tgid */
	__type(value, struct infer_state);
} infer_states SEC(".maps");

GADGET_TRACER_MAP(ttft_events, 262144);
GADGET_TRACER(ttft, ttft_events, ttft_event);

GADGET_TRACER_MAP(token_events, 1048576);
GADGET_TRACER(tokens, token_events, token_event);

GADGET_TRACER_MAP(request_events, 262144);
GADGET_TRACER(requests, request_events, request_event);

/* ════════════════════════════════════════════════════════════════════════
 *  Helpers
 * ════════════════════════════════════════════════════════════════════════ */

SEC("tracepoint/sched/sched_process_exit")
int trace_sched_process_exit(void *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tid  = (u32)pid_tgid;
	u32 tgid = (u32)(pid_tgid >> 32);

	bpf_map_delete_elem(&sizes, &tid);
	bpf_map_delete_elem(&sync_entry, &tid);
	if (tid == tgid)
		bpf_map_delete_elem(&infer_states, &tgid);
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

/* ─── Memcpy emit helper ─── */

static __always_inline void emit_memcpy(void *ctx, __u64 size, __u32 dir,
					 __u32 is_async)
{
	if (gadget_should_discard_data_current())
		return;
	struct memcpy_event *evt =
		gadget_reserve_buf(&memcpy_events, sizeof(*evt));
	if (!evt)
		return;
	__builtin_memset(evt, 0, sizeof(*evt));
	gadget_process_populate(&evt->proc);
	evt->timestamp_ns = bpf_ktime_get_ns();
	evt->size_bytes = size;
	evt->direction = dir;
	evt->is_async = is_async;
	gadget_submit_buf(ctx, &memcpy_events, evt, sizeof(*evt));
}

/* ─── Context event helper ─── */

static __always_inline void emit_ctx(void *ctx, __u32 etype)
{
	if (gadget_should_discard_data_current())
		return;
	struct ctx_event *evt =
		gadget_reserve_buf(&ctx_events, sizeof(*evt));
	if (!evt)
		return;
	__builtin_memset(evt, 0, sizeof(*evt));
	gadget_process_populate(&evt->proc);
	evt->timestamp_ns = bpf_ktime_get_ns();
	evt->event_type = etype;
	gadget_submit_buf(ctx, &ctx_events, evt, sizeof(*evt));
}

/* ─── Launch event helper ─── */

static __always_inline void emit_launch(void *ctx, __u64 now, __u32 ltype)
{
	if (gadget_should_discard_data_current())
		return;
	struct launch_event *evt =
		gadget_reserve_buf(&launch_events, sizeof(*evt));
	if (!evt)
		return;
	__builtin_memset(evt, 0, sizeof(*evt));
	gadget_process_populate(&evt->proc);
	evt->timestamp_ns = now;
	evt->launch_type = ltype;
	gadget_submit_buf(ctx, &launch_events, evt, sizeof(*evt));
}

/* ─── Inference metric helpers ─── */

static __always_inline struct infer_state *get_or_init_state(__u32 tgid)
{
	struct infer_state *st = bpf_map_lookup_elem(&infer_states, &tgid);
	if (st)
		return st;
	struct infer_state new_st = {};
	new_st.detected_stack = stack_hint;
	bpf_map_update_elem(&infer_states, &tgid, &new_st, BPF_NOEXIST);
	return bpf_map_lookup_elem(&infer_states, &tgid);
}

static __always_inline __u32 auto_detect_stack(struct infer_state *st)
{
	if (stack_hint != STACK_AUTO)
		return stack_hint;
	if (st->memcpy_asyncs > 0 && st->dtoh_asyncs == 0 &&
	    st->graph_launches == 0)
		return STACK_TRTLLM;
	if (st->graph_launches > 0 && st->event_syncs > 0)
		return STACK_VLLM;
	if (st->graph_launches > 0 && st->event_syncs == 0)
		return STACK_LLAMACPP;
	if (st->graph_launches > 0 &&
	    st->kernel_launches > st->graph_launches * 5)
		return STACK_TGI;
	if (st->kernel_launches > 0 && st->graph_launches == 0 &&
	    st->event_syncs == 0)
		return STACK_HF_SDPA;
	return STACK_AUTO;
}

static __always_inline void emit_token(void *ctx, struct infer_state *st,
					__u64 now)
{
	__u64 itl = st->last_token_ns ? now - st->last_token_ns : 0;

	struct token_event *evt =
		gadget_reserve_buf(&token_events, sizeof(*evt));
	if (evt) {
		__builtin_memset(evt, 0, sizeof(*evt));
		gadget_process_populate(&evt->proc);
		evt->timestamp_ns = now;
		evt->inter_token_ns = itl;
		evt->token_index = st->decode_tokens;
		evt->detected_stack = st->detected_stack;
		gadget_submit_buf(ctx, &token_events, evt, sizeof(*evt));
	}

	/* SLO: update streaming smoothness stats */
	if (itl > 0) {
		st->itl_sum_ns += itl;
		/* Track max/min for jitter calculation */
		if (itl > st->itl_max_ns)
			st->itl_max_ns = itl;
		if (st->itl_min_ns == 0 || itl < st->itl_min_ns)
			st->itl_min_ns = itl;
		/*
		 * Accumulate sum of squares / 1000000 to avoid overflow.
		 * itl is in ns, divide by 1000 (us), square, accumulate.
		 * This gives us variance in us^2 units.
		 */
		__u64 itl_us = itl / 1000;
		st->itl_sum_sq_ns += itl_us * itl_us;
	}

	if (st->decode_tokens == 0)
		st->first_token_ns = now;
	st->last_token_ns = now;
	st->decode_tokens++;
}

static __always_inline void emit_request_complete(void *ctx,
						   struct infer_state *st,
						   __u64 now)
{
	if (st->decode_tokens == 0)
		return;
	struct request_event *evt =
		gadget_reserve_buf(&request_events, sizeof(*evt));
	if (evt) {
		__builtin_memset(evt, 0, sizeof(*evt));
		gadget_process_populate(&evt->proc);
		evt->e2e_latency_ns = now - st->prefill_start_ns;
		evt->ttft_ns = st->first_token_ns - st->prefill_start_ns;
		evt->decode_duration_ns =
			st->last_token_ns - st->first_token_ns;
		evt->total_tokens = st->decode_tokens;
		evt->detected_stack = st->detected_stack;

		/* SLO: streaming smoothness */
		evt->itl_max_ns = st->itl_max_ns;
		evt->itl_min_ns = st->itl_min_ns;
		if (st->decode_tokens > 1)
			evt->itl_avg_ns =
				st->itl_sum_ns / (st->decode_tokens - 1);
		else
			evt->itl_avg_ns = 0;
		evt->itl_jitter_ns = st->itl_max_ns - st->itl_min_ns;

		/* SLO: long context flag */
		evt->is_long_context = st->is_long_context;

		gadget_submit_buf(ctx, &request_events, evt, sizeof(*evt));
	}
}

static __always_inline void handle_kernel(void *ctx, __u64 now, int is_graph)
{
	if (gadget_should_discard_data_current())
		return;

	u32 tgid = (u32)(bpf_get_current_pid_tgid() >> 32);
	struct infer_state *st = get_or_init_state(tgid);
	if (!st)
		return;

	if (is_graph)
		st->graph_launches++;
	else
		st->kernel_launches++;

	u64 gap = now - st->last_kernel_ns;

	switch (st->phase) {
	case PHASE_IDLE:
		st->phase = PHASE_PREFILL;
		st->prefill_start_ns = now;
		st->last_kernel_ns = now;
		st->prefill_kernels = 1;
		st->decode_tokens = 0;
		st->first_token_ns = 0;
		st->last_token_ns = 0;
		st->req_event_syncs = 0;
		st->req_dtoh_asyncs = 0;
		/* SLO: reset streaming stats */
		st->itl_max_ns = 0;
		st->itl_min_ns = 0;
		st->itl_sum_ns = 0;
		st->itl_sum_sq_ns = 0;
		st->is_long_context = 0;
		break;

	case PHASE_PREFILL:
		if (gap > gap_threshold_ns &&
		    st->prefill_kernels >= min_prefill_kernels) {
			st->detected_stack = auto_detect_stack(st);
			struct ttft_event *evt =
				gadget_reserve_buf(&ttft_events, sizeof(*evt));
			if (evt) {
				__builtin_memset(evt, 0, sizeof(*evt));
				gadget_process_populate(&evt->proc);
				evt->ttft_ns =
					st->last_kernel_ns -
					st->prefill_start_ns;
				evt->prefill_kernels = st->prefill_kernels;
				evt->prefill_start = st->prefill_start_ns;
				evt->prefill_end = st->last_kernel_ns;
				evt->detected_stack = st->detected_stack;
				gadget_submit_buf(ctx, &ttft_events,
						  evt, sizeof(*evt));
			}
			st->phase = PHASE_DECODE;
		}
		st->last_kernel_ns = now;
		st->prefill_kernels++;

		/* SLO: long context detection and alert */
		if (st->prefill_kernels == long_ctx_kernels) {
			st->is_long_context = 1;
			struct long_ctx_event *lce =
				gadget_reserve_buf(&long_ctx_events,
						   sizeof(*lce));
			if (lce) {
				__builtin_memset(lce, 0, sizeof(*lce));
				gadget_process_populate(&lce->proc);
				lce->timestamp_ns = now;
				lce->prefill_kernels = st->prefill_kernels;
				lce->estimated_ttft_ns =
					now - st->prefill_start_ns;
				gadget_submit_buf(ctx, &long_ctx_events,
						  lce, sizeof(*lce));
			}
		}
		break;

	case PHASE_DECODE:
		if (gap > cooldown_ns) {
			emit_request_complete(ctx, st, st->last_token_ns);
			st->phase = PHASE_PREFILL;
			st->prefill_start_ns = now;
			st->prefill_kernels = 1;
			st->decode_tokens = 0;
			st->first_token_ns = 0;
			st->last_token_ns = 0;
			st->req_event_syncs = 0;
			st->req_dtoh_asyncs = 0;
			/* SLO: reset streaming stats */
			st->itl_max_ns = 0;
			st->itl_min_ns = 0;
			st->itl_sum_ns = 0;
			st->itl_sum_sq_ns = 0;
			st->is_long_context = 0;
		}
		st->last_kernel_ns = now;
		break;
	}
}

static __always_inline void handle_token_signal(void *ctx, __u64 now,
						 int signal_type)
{
	if (gadget_should_discard_data_current())
		return;

	u32 tgid = (u32)(bpf_get_current_pid_tgid() >> 32);
	struct infer_state *st = bpf_map_lookup_elem(&infer_states, &tgid);
	if (!st || st->phase != PHASE_DECODE)
		return;

	switch (signal_type) {
	case 2: st->dtoh_asyncs++; st->req_dtoh_asyncs++; break;
	case 3: st->event_syncs++; st->req_event_syncs++; break;
	case 4: st->stream_syncs++; break;
	case 5: st->memcpy_asyncs++; break;
	}

	__u32 stack = st->detected_stack;
	if (stack == STACK_AUTO ||
	    (st->decode_tokens > 0 && st->decode_tokens % 10 == 0))
		stack = auto_detect_stack(st);
	if (stack != st->detected_stack)
		st->detected_stack = stack;

	int is_token = 0;
	switch (stack) {
	case STACK_LLAMACPP:
	case STACK_VLLM:
	case STACK_TGI:
		is_token = (signal_type == 1);
		break;
	case STACK_TRTLLM:
		is_token = (signal_type == 3 &&
			    (st->req_event_syncs % 2 == 0));
		break;
	case STACK_HF_SDPA:
		is_token = (signal_type == 2 &&
			    (st->req_dtoh_asyncs % 2 == 0));
		break;
	default:
		if (st->graph_launches > 0)
			is_token = (signal_type == 1);
		else if (st->event_syncs > 0)
			is_token = (signal_type == 3);
		else
			is_token = (signal_type == 2);
		break;
	}

	if (is_token)
		emit_token(ctx, st, now);
}

/* ════════════════════════════════════════════════════════════════════════
 *  Probes: Kernel Launch
 * ════════════════════════════════════════════════════════════════════════ */

SEC("uprobe/libcuda:cuLaunchKernel")
int BPF_UPROBE(trace_uprobe_cuLaunchKernel)
{
	u64 now = bpf_ktime_get_ns();
	handle_kernel(ctx, now, 0);
	emit_launch(ctx, now, LAUNCH_KERNEL);
	return 0;
}

SEC("uprobe/libcuda:cuLaunchKernelEx")
int BPF_UPROBE(trace_uprobe_cuLaunchKernelEx)
{
	u64 now = bpf_ktime_get_ns();
	handle_kernel(ctx, now, 0);
	emit_launch(ctx, now, LAUNCH_KERNEL);
	return 0;
}

SEC("uprobe/libcuda:cuGraphLaunch")
int BPF_UPROBE(trace_uprobe_cuGraphLaunch)
{
	u64 now = bpf_ktime_get_ns();
	handle_kernel(ctx, now, 1);
	handle_token_signal(ctx, now, 1);
	emit_launch(ctx, now, LAUNCH_GRAPH);
	return 0;
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
	u64 now = bpf_ktime_get_ns();
	handle_token_signal(ctx, now, 4);
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
	u64 now = bpf_ktime_get_ns();
	handle_token_signal(ctx, now, 3);
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
 *  Probes: Memory Transfers
 * ════════════════════════════════════════════════════════════════════════ */

SEC("uprobe/libcuda:cuMemcpyHtoD_v2")
int BPF_UPROBE(trace_uprobe_cuMemcpyHtoD_v2, void *dst, void *src,
	       size_t size)
{
	emit_memcpy(ctx, size, DIR_HTOD, 0);
	return 0;
}

SEC("uprobe/libcuda:cuMemcpyHtoDAsync_v2")
int BPF_UPROBE(trace_uprobe_cuMemcpyHtoDAsync_v2, void *dst, void *src,
	       size_t size)
{
	emit_memcpy(ctx, size, DIR_HTOD, 1);
	return 0;
}

SEC("uprobe/libcuda:cuMemcpyDtoH_v2")
int BPF_UPROBE(trace_uprobe_cuMemcpyDtoH_v2, void *dst, void *src,
	       size_t size)
{
	emit_memcpy(ctx, size, DIR_DTOH, 0);
	handle_token_signal(ctx, bpf_ktime_get_ns(), 2);
	return 0;
}

SEC("uprobe/libcuda:cuMemcpyDtoHAsync_v2")
int BPF_UPROBE(trace_uprobe_cuMemcpyDtoHAsync_v2, void *dst, void *src,
	       size_t size)
{
	emit_memcpy(ctx, size, DIR_DTOH, 1);
	handle_token_signal(ctx, bpf_ktime_get_ns(), 2);
	return 0;
}

SEC("uprobe/libcuda:cuMemcpyDtoD_v2")
int BPF_UPROBE(trace_uprobe_cuMemcpyDtoD_v2, void *dst, void *src,
	       size_t size)
{
	emit_memcpy(ctx, size, DIR_DTOD, 0);
	return 0;
}

SEC("uprobe/libcuda:cuMemcpyDtoDAsync_v2")
int BPF_UPROBE(trace_uprobe_cuMemcpyDtoDAsync_v2, void *dst, void *src,
	       size_t size)
{
	emit_memcpy(ctx, size, DIR_DTOD, 1);
	return 0;
}

SEC("uprobe/libcuda:cuMemcpyAsync")
int BPF_UPROBE(trace_uprobe_cuMemcpyAsync)
{
	handle_token_signal(ctx, bpf_ktime_get_ns(), 5);
	return 0;
}

SEC("uprobe/libcuda:cuMemcpyPeer")
int BPF_UPROBE(trace_uprobe_cuMemcpyPeer, void *dst, void *dstCtx,
	       void *src, void *srcCtx, size_t size)
{
	emit_memcpy(ctx, size, DIR_PEER, 0);
	return 0;
}

SEC("uprobe/libcuda:cuMemcpyPeerAsync")
int BPF_UPROBE(trace_uprobe_cuMemcpyPeerAsync, void *dst, void *dstCtx,
	       void *src, void *srcCtx, size_t size)
{
	emit_memcpy(ctx, size, DIR_PEER, 1);
	return 0;
}

/* ════════════════════════════════════════════════════════════════════════
 *  Probes: Context Lifecycle
 * ════════════════════════════════════════════════════════════════════════ */

SEC("uprobe/libcuda:cuCtxCreate_v2")
int BPF_UPROBE(trace_uprobe_cuCtxCreate_v2)
{
	emit_ctx(ctx, CTX_CREATE);
	return 0;
}

SEC("uprobe/libcuda:cuCtxCreate_v3")
int BPF_UPROBE(trace_uprobe_cuCtxCreate_v3)
{
	emit_ctx(ctx, CTX_CREATE);
	return 0;
}

SEC("uprobe/libcuda:cuCtxDestroy_v2")
int BPF_UPROBE(trace_uprobe_cuCtxDestroy_v2)
{
	emit_ctx(ctx, CTX_DESTROY);
	return 0;
}

SEC("uprobe/libcuda:cuCtxSetCurrent")
int BPF_UPROBE(trace_uprobe_cuCtxSetCurrent)
{
	emit_ctx(ctx, CTX_SET);
	return 0;
}

/* ════════════════════════════════════════════════════════════════════════
 *  Probes: Module Load
 * ════════════════════════════════════════════════════════════════════════ */

SEC("uretprobe/libcuda:cuModuleLoad")
int trace_uretprobe_cuModuleLoad(struct pt_regs *ctx)
{
	emit_error(ctx, API_ID_MODULE_LOAD, PT_REGS_RC(ctx));
	return 0;
}

SEC("uretprobe/libcuda:cuModuleLoadData")
int trace_uretprobe_cuModuleLoadData(struct pt_regs *ctx)
{
	emit_error(ctx, API_ID_MODULE_LOAD_DATA, PT_REGS_RC(ctx));
	return 0;
}

SEC("uretprobe/libcuda:cuModuleLoadDataEx")
int trace_uretprobe_cuModuleLoadDataEx(struct pt_regs *ctx)
{
	emit_error(ctx, API_ID_MODULE_LOAD_DATA, PT_REGS_RC(ctx));
	return 0;
}

/* ════════════════════════════════════════════════════════════════════════
 *  Probes: P2P
 * ════════════════════════════════════════════════════════════════════════ */

SEC("uretprobe/libcuda:cuCtxEnablePeerAccess")
int trace_uretprobe_cuCtxEnablePeerAccess(struct pt_regs *ctx)
{
	emit_error(ctx, API_ID_P2P_ENABLE, PT_REGS_RC(ctx));
	return 0;
}

/* ════════════════════════════════════════════════════════════════════════
 *  Probes: Graph Instantiation
 * ════════════════════════════════════════════════════════════════════════ */

SEC("uretprobe/libcuda:cuGraphInstantiate")
int trace_uretprobe_cuGraphInstantiate(struct pt_regs *ctx)
{
	emit_error(ctx, API_ID_GRAPH_INSTANTIATE, PT_REGS_RC(ctx));
	return 0;
}

SEC("uretprobe/libcuda:cuGraphInstantiateWithFlags")
int trace_uretprobe_cuGraphInstantiateWithFlags(struct pt_regs *ctx)
{
	emit_error(ctx, API_ID_GRAPH_INSTANTIATE, PT_REGS_RC(ctx));
	return 0;
}

SEC("uretprobe/libcuda:cuGraphInstantiateWithParams")
int trace_uretprobe_cuGraphInstantiateWithParams(struct pt_regs *ctx)
{
	emit_error(ctx, API_ID_GRAPH_INSTANTIATE, PT_REGS_RC(ctx));
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
