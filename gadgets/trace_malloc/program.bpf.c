// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2024 The Inspektor Gadget authors */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <gadget/types.h>
#include <gadget/buffer.h>
#include <gadget/common.h>
#include <gadget/filter.h>
#include <gadget/macros.h>
#include <gadget/user_stack_map.h>

#define MAX_ENTRIES 10240

/* Configurable parameter: capture user-space stacks (default: true) */
const volatile bool capture_stacks = true;

GADGET_PARAM(capture_stacks);


enum memop {
	malloc,
	free,
	calloc,
	realloc,
	realloc_free,
	mmap,
	munmap,
	posix_memalign,
	aligned_alloc,
	valloc,
	memalign,
	pvalloc,
	op_new,
	op_new_array,
	op_delete,
	op_delete_array,
	reallocarray,
};

struct event {
	gadget_timestamp timestamp_raw;
	struct gadget_process proc;

	struct gadget_user_stack ustack;

	enum memop operation_raw;
	__u64 addr;
	__u64 size;
};

/* used for context between uprobes and uretprobes of allocations */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32); // tid
	__type(value, u64);
} sizes SEC(".maps");
/* Per-thread size stash for C++ operator new probes; kept separate from the
 * libc `sizes` map so that an inner libc malloc call (which libstdc++'s
 * _Znwm implementation makes) cannot overwrite the outer C++ value before
 * the operator's uretprobe consumes it. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32); // tid
	__type(value, u64);
} cxx_sizes SEC(".maps");

/* Separate per-thread size stash for C++ array-new (_Znam family). libstdc++
 * implements _Znam by internally calling _Znwm, so a single cxx_sizes map
 * would be overwritten by the inner _Znwm uprobe before the outer _Znam
 * uretprobe could read it (root cause of op_new_array=0 events). Keep a
 * dedicated map for the array path. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32); // tid
	__type(value, u64);
} cxx_array_sizes SEC(".maps");


/* used by posix_memalign */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32); // tid
	__type(value, u64);
} memptrs SEC(".maps");

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
	bpf_map_delete_elem(&cxx_sizes, &tid);
	bpf_map_delete_elem(&cxx_array_sizes, &tid);
	bpf_map_delete_elem(&memptrs, &tid);
	return 0;
}

GADGET_TRACER_MAP(events, 1024 * 256);
GADGET_TRACER(malloc, events, event);

static __always_inline int gen_alloc_enter(size_t size)
{
	u32 tid;

	tid = (u32)bpf_get_current_pid_tgid();
	bpf_map_update_elem(&sizes, &tid, &size, BPF_ANY);

	return 0;
}

static __always_inline int gen_alloc_exit(struct pt_regs *ctx,
					  enum memop operation, u64 addr)
{
	struct event *event;
	u64 pid_tgid;
	u32 tid;
	u64 *size_ptr;
	u64 size;

	if (gadget_should_discard_data_current())
		return 0;

	pid_tgid = bpf_get_current_pid_tgid();
	tid = (u32)pid_tgid;
	size_ptr = bpf_map_lookup_elem(&sizes, &tid);
	if (!size_ptr)
		return 0;
	size = *size_ptr;
	bpf_map_delete_elem(&sizes, &tid);

	event = gadget_reserve_buf(&events, sizeof(*event));
	if (!event)
		return 0;

	gadget_process_populate(&event->proc);
	event->operation_raw = operation;
	event->addr = addr;
	event->size = size;
	event->timestamp_raw = bpf_ktime_get_ns();

	if (capture_stacks)
		gadget_get_user_stack(ctx, &event->ustack);

	gadget_submit_buf(ctx, &events, event, sizeof(*event));

	return 0;
}

static __always_inline int gen_free_enter(struct pt_regs *ctx,
					  enum memop operation, u64 addr)
{
	struct event *event;

	if (gadget_should_discard_data_current())
		return 0;

	event = gadget_reserve_buf(&events, sizeof(*event));
	if (!event)
		return 0;

	gadget_process_populate(&event->proc);
	event->operation_raw = operation;
	event->addr = addr;
	event->size = 0;
	event->timestamp_raw = bpf_ktime_get_ns();

	if (capture_stacks)
		gadget_get_user_stack(ctx, &event->ustack);

	gadget_submit_buf(ctx, &events, event, sizeof(*event));

	return 0;
}


static __always_inline int gen_cxx_alloc_enter(size_t size)
{
	u32 tid = (u32)bpf_get_current_pid_tgid();
	bpf_map_update_elem(&cxx_sizes, &tid, &size, BPF_ANY);
	return 0;
}

static __always_inline int gen_cxx_alloc_exit(struct pt_regs *ctx,
					      enum memop operation, u64 addr)
{
	struct event *event;
	u32 tid;
	u64 *size_ptr;
	u64 size;

	if (gadget_should_discard_data_current())
		return 0;

	tid = (u32)bpf_get_current_pid_tgid();
	size_ptr = bpf_map_lookup_elem(&cxx_sizes, &tid);
	if (!size_ptr)
		return 0;
	size = *size_ptr;
	bpf_map_delete_elem(&cxx_sizes, &tid);

	event = gadget_reserve_buf(&events, sizeof(*event));
	if (!event)
		return 0;

	event->timestamp_raw = bpf_ktime_get_boot_ns();
	event->operation_raw = operation;
	event->addr = addr;
	event->size = size;
	gadget_process_populate(&event->proc);
	if (capture_stacks)
		gadget_get_user_stack(ctx, &event->ustack);
	gadget_submit_buf(ctx, &events, event, sizeof(*event));
	return 0;
}

static __always_inline int gen_cxx_array_alloc_enter(size_t size)
{
	u32 tid = (u32)bpf_get_current_pid_tgid();
	bpf_map_update_elem(&cxx_array_sizes, &tid, &size, BPF_ANY);
	return 0;
}

static __always_inline int gen_cxx_array_alloc_exit(struct pt_regs *ctx,
						    enum memop operation, u64 addr)
{
	struct event *event;
	u32 tid;
	u64 *size_ptr;
	u64 size;

	if (gadget_should_discard_data_current())
		return 0;

	tid = (u32)bpf_get_current_pid_tgid();
	size_ptr = bpf_map_lookup_elem(&cxx_array_sizes, &tid);
	if (!size_ptr)
		return 0;
	size = *size_ptr;
	bpf_map_delete_elem(&cxx_array_sizes, &tid);

	event = gadget_reserve_buf(&events, sizeof(*event));
	if (!event)
		return 0;

	event->timestamp_raw = bpf_ktime_get_boot_ns();
	event->operation_raw = operation;
	event->addr = addr;
	event->size = size;
	gadget_process_populate(&event->proc);
	if (capture_stacks)
		gadget_get_user_stack(ctx, &event->ustack);
	gadget_submit_buf(ctx, &events, event, sizeof(*event));
	return 0;
}

/* common macros */
#define PROBE_RET_VAL_FOR_ALLOC(func)                              \
	SEC("uretprobe/libc:" #func)                               \
	int trace_uretprobe_##func(struct pt_regs *ctx)            \
	{                                                          \
		return gen_alloc_exit(ctx, func, PT_REGS_RC(ctx)); \
	}

/* malloc */
SEC("uprobe/libc:malloc")
int BPF_UPROBE(trace_uprobe_malloc, size_t size)
{
	return gen_alloc_enter(size);
}

PROBE_RET_VAL_FOR_ALLOC(malloc)

/* free */
SEC("uprobe/libc:free")
int BPF_UPROBE(trace_uprobe_free, void *address)
{
	return gen_free_enter(ctx, free, (u64)address);
}

/* calloc */
SEC("uprobe/libc:calloc")
int BPF_UPROBE(trace_uprobe_calloc, size_t nmemb, size_t size)
{
	return gen_alloc_enter(nmemb * size);
}

PROBE_RET_VAL_FOR_ALLOC(calloc)

/* realloc */
SEC("uprobe/libc:realloc")
int BPF_UPROBE(trace_uprobe_realloc, void *ptr, size_t size)
{
	gen_free_enter(ctx, realloc_free, (u64)ptr);
	return gen_alloc_enter(size);
}

PROBE_RET_VAL_FOR_ALLOC(realloc)

/* mmap */
SEC("uprobe/libc:mmap")
int BPF_UPROBE(trace_uprobe_mmap, void *address, size_t size)
{
	return gen_alloc_enter(size);
}

PROBE_RET_VAL_FOR_ALLOC(mmap)

/* munmap */
SEC("uprobe/libc:munmap")
int BPF_UPROBE(trace_uprobe_munmap, void *address)
{
	return gen_free_enter(ctx, munmap, (u64)address);
}

/* posix_memalign */
SEC("uprobe/libc:posix_memalign")
int BPF_UPROBE(trace_uprobe_posix_memalign, void **memptr, size_t alignment,
	       size_t size)
{
	u64 memptr64;
	u32 tid;

	tid = (u32)bpf_get_current_pid_tgid();
	memptr64 = (u64)memptr;
	bpf_map_update_elem(&memptrs, &tid, &memptr64, BPF_ANY);

	return gen_alloc_enter(size);
}

SEC("uretprobe/libc:posix_memalign")
int trace_uretprobe_posix_memalign(struct pt_regs *ctx)
{
	u64 *memptr64;
	void *addr;
	u32 tid;

	tid = (u32)bpf_get_current_pid_tgid();

	memptr64 = bpf_map_lookup_elem(&memptrs, &tid);
	if (!memptr64)
		return 0;
	bpf_map_delete_elem(&memptrs, &tid);

	if (bpf_probe_read_user(&addr, sizeof(void *), (void *)*memptr64))
		return 0;

	return gen_alloc_exit(ctx, posix_memalign, (u64)addr);
}

/* aligned_alloc */
SEC("uprobe/libc:aligned_alloc")
int BPF_UPROBE(trace_uprobe_aligned_alloc, size_t alignment, size_t size)
{
	return gen_alloc_enter(size);
}

PROBE_RET_VAL_FOR_ALLOC(aligned_alloc)

/* valloc */
SEC("uprobe/libc:valloc")
int BPF_UPROBE(trace_uprobe_valloc, size_t size)
{
	return gen_alloc_enter(size);
}

PROBE_RET_VAL_FOR_ALLOC(valloc)

/* memalign */
SEC("uprobe/libc:memalign")
int BPF_UPROBE(trace_uprobe_memalign, size_t alignment, size_t size)
{
	return gen_alloc_enter(size);
}

PROBE_RET_VAL_FOR_ALLOC(memalign)

/* pvalloc */
SEC("uprobe/libc:pvalloc")
int BPF_UPROBE(trace_uprobe_pvalloc, size_t size)
{
	return gen_alloc_enter(size);
}

PROBE_RET_VAL_FOR_ALLOC(pvalloc)

/* C++ operator new (_Znwm) */
SEC("uprobe/libstdc++:_Znwm")
int BPF_UPROBE(trace_uprobe_new, size_t size)
{
	return gen_cxx_alloc_enter(size);
}

SEC("uretprobe/libstdc++:_Znwm")
int trace_uretprobe_new(struct pt_regs *ctx)
{
	return gen_cxx_alloc_exit(ctx, op_new, PT_REGS_RC(ctx));
}

/* C++ operator new[] (_Znam) */
SEC("uprobe/libstdc++:_Znam")
int BPF_UPROBE(trace_uprobe_new_array, size_t size)
{
	return gen_cxx_array_alloc_enter(size);
}

SEC("uretprobe/libstdc++:_Znam")
int trace_uretprobe_new_array(struct pt_regs *ctx)
{
	return gen_cxx_array_alloc_exit(ctx, op_new_array, PT_REGS_RC(ctx));
}

/* C++ operator delete (_ZdlPv) */
SEC("uprobe/libstdc++:_ZdlPv")
int BPF_UPROBE(trace_uprobe_delete, void *address)
{
	return gen_free_enter(ctx, op_delete, (u64)address);
}

/* C++ operator delete[] (_ZdaPv) */
SEC("uprobe/libstdc++:_ZdaPv")
int BPF_UPROBE(trace_uprobe_delete_array, void *address)
{
	return gen_free_enter(ctx, op_delete_array, (u64)address);
}

/* reallocarray */
SEC("uprobe/libc:reallocarray")
int BPF_UPROBE(trace_uprobe_reallocarray, void *ptr, size_t nmemb, size_t size)
{
	gen_free_enter(ctx, realloc_free, (u64)ptr);
	return gen_alloc_enter(nmemb * size);
}

SEC("uretprobe/libc:reallocarray")
int trace_uretprobe_reallocarray(struct pt_regs *ctx)
{
	return gen_alloc_exit(ctx, reallocarray, PT_REGS_RC(ctx));
}


/* C++17 aligned operator new (_ZnwmSt11align_val_t) */
SEC("uprobe/libstdc++:_ZnwmSt11align_val_t")
int BPF_UPROBE(trace_uprobe_new_aligned, size_t size)
{
	return gen_cxx_alloc_enter(size);
}

SEC("uretprobe/libstdc++:_ZnwmSt11align_val_t")
int trace_uretprobe_new_aligned(struct pt_regs *ctx)
{
	return gen_cxx_alloc_exit(ctx, op_new, PT_REGS_RC(ctx));
}

/* C++17 aligned operator new[] (_ZnamSt11align_val_t) */
SEC("uprobe/libstdc++:_ZnamSt11align_val_t")
int BPF_UPROBE(trace_uprobe_new_array_aligned, size_t size)
{
	return gen_cxx_array_alloc_enter(size);
}

SEC("uretprobe/libstdc++:_ZnamSt11align_val_t")
int trace_uretprobe_new_array_aligned(struct pt_regs *ctx)
{
	return gen_cxx_array_alloc_exit(ctx, op_new_array, PT_REGS_RC(ctx));
}

/* nothrow operator new (_ZnwmRKSt9nothrow_t) */
SEC("uprobe/libstdc++:_ZnwmRKSt9nothrow_t")
int BPF_UPROBE(trace_uprobe_new_nothrow, size_t size)
{
	return gen_cxx_alloc_enter(size);
}

SEC("uretprobe/libstdc++:_ZnwmRKSt9nothrow_t")
int trace_uretprobe_new_nothrow(struct pt_regs *ctx)
{
	return gen_cxx_alloc_exit(ctx, op_new, PT_REGS_RC(ctx));
}

/* nothrow operator new[] (_ZnamRKSt9nothrow_t) */
SEC("uprobe/libstdc++:_ZnamRKSt9nothrow_t")
int BPF_UPROBE(trace_uprobe_new_array_nothrow, size_t size)
{
	return gen_cxx_array_alloc_enter(size);
}

SEC("uretprobe/libstdc++:_ZnamRKSt9nothrow_t")
int trace_uretprobe_new_array_nothrow(struct pt_regs *ctx)
{
	return gen_cxx_array_alloc_exit(ctx, op_new_array, PT_REGS_RC(ctx));
}

/* sized operator delete (_ZdlPvm) */
SEC("uprobe/libstdc++:_ZdlPvm")
int BPF_UPROBE(trace_uprobe_delete_sized, void *address, size_t size)
{
	return gen_free_enter(ctx, op_delete, (u64)address);
}

/* sized operator delete[] (_ZdaPvm) */
SEC("uprobe/libstdc++:_ZdaPvm")
int BPF_UPROBE(trace_uprobe_delete_array_sized, void *address, size_t size)
{
	return gen_free_enter(ctx, op_delete_array, (u64)address);
}

/* aligned operator delete (_ZdlPvSt11align_val_t) */
SEC("uprobe/libstdc++:_ZdlPvSt11align_val_t")
int BPF_UPROBE(trace_uprobe_delete_aligned, void *address)
{
	return gen_free_enter(ctx, op_delete, (u64)address);
}

/* aligned operator delete[] (_ZdaPvSt11align_val_t) */
SEC("uprobe/libstdc++:_ZdaPvSt11align_val_t")
int BPF_UPROBE(trace_uprobe_delete_array_aligned, void *address)
{
	return gen_free_enter(ctx, op_delete_array, (u64)address);
}


/* libc++ (Clang/LLVM) parallel attachments - same Itanium ABI mangling */
SEC("uprobe/libc++:_ZdaPv")
int BPF_UPROBE(trace_cxx_uprobe__ZdaPv, void *address) { return gen_free_enter(ctx, op_delete, (u64)address); }

SEC("uprobe/libc++:_ZdaPvSt11align_val_t")
int BPF_UPROBE(trace_cxx_uprobe__ZdaPvSt11align_val_t, void *address) { return gen_free_enter(ctx, op_delete, (u64)address); }

SEC("uprobe/libc++:_ZdaPvm")
int BPF_UPROBE(trace_cxx_uprobe__ZdaPvm, void *address) { return gen_free_enter(ctx, op_delete, (u64)address); }

SEC("uprobe/libc++:_ZdlPv")
int BPF_UPROBE(trace_cxx_uprobe__ZdlPv, void *address) { return gen_free_enter(ctx, op_delete, (u64)address); }

SEC("uprobe/libc++:_ZdlPvSt11align_val_t")
int BPF_UPROBE(trace_cxx_uprobe__ZdlPvSt11align_val_t, void *address) { return gen_free_enter(ctx, op_delete, (u64)address); }

SEC("uprobe/libc++:_ZdlPvm")
int BPF_UPROBE(trace_cxx_uprobe__ZdlPvm, void *address) { return gen_free_enter(ctx, op_delete, (u64)address); }

SEC("uprobe/libc++:_Znam")
int BPF_UPROBE(trace_cxx_uprobe__Znam, size_t size) { return gen_cxx_array_alloc_enter(size); }

SEC("uprobe/libc++:_ZnamRKSt9nothrow_t")
int BPF_UPROBE(trace_cxx_uprobe__ZnamRKSt9nothrow_t, size_t size) { return gen_cxx_array_alloc_enter(size); }

SEC("uprobe/libc++:_ZnamSt11align_val_t")
int BPF_UPROBE(trace_cxx_uprobe__ZnamSt11align_val_t, size_t size) { return gen_cxx_array_alloc_enter(size); }

SEC("uprobe/libc++:_Znwm")
int BPF_UPROBE(trace_cxx_uprobe__Znwm, size_t size) { return gen_cxx_alloc_enter(size); }

SEC("uprobe/libc++:_ZnwmRKSt9nothrow_t")
int BPF_UPROBE(trace_cxx_uprobe__ZnwmRKSt9nothrow_t, size_t size) { return gen_cxx_alloc_enter(size); }

SEC("uprobe/libc++:_ZnwmSt11align_val_t")
int BPF_UPROBE(trace_cxx_uprobe__ZnwmSt11align_val_t, size_t size) { return gen_cxx_alloc_enter(size); }

SEC("uretprobe/libc++:_Znam")
int trace_cxx_uretprobe__Znam(struct pt_regs *ctx) { return gen_cxx_array_alloc_exit(ctx, op_new_array, PT_REGS_RC(ctx)); }

SEC("uretprobe/libc++:_ZnamRKSt9nothrow_t")
int trace_cxx_uretprobe__ZnamRKSt9nothrow_t(struct pt_regs *ctx) { return gen_cxx_array_alloc_exit(ctx, op_new_array, PT_REGS_RC(ctx)); }

SEC("uretprobe/libc++:_ZnamSt11align_val_t")
int trace_cxx_uretprobe__ZnamSt11align_val_t(struct pt_regs *ctx) { return gen_cxx_array_alloc_exit(ctx, op_new_array, PT_REGS_RC(ctx)); }

SEC("uretprobe/libc++:_Znwm")
int trace_cxx_uretprobe__Znwm(struct pt_regs *ctx) { return gen_cxx_alloc_exit(ctx, op_new, PT_REGS_RC(ctx)); }

SEC("uretprobe/libc++:_ZnwmRKSt9nothrow_t")
int trace_cxx_uretprobe__ZnwmRKSt9nothrow_t(struct pt_regs *ctx) { return gen_cxx_alloc_exit(ctx, op_new, PT_REGS_RC(ctx)); }

SEC("uretprobe/libc++:_ZnwmSt11align_val_t")
int trace_cxx_uretprobe__ZnwmSt11align_val_t(struct pt_regs *ctx) { return gen_cxx_alloc_exit(ctx, op_new, PT_REGS_RC(ctx)); }



/* libc++abi.so.1 attachments - Clang/LLVM operator implementations live here */
SEC("uprobe/libc++abi:_ZdaPv")
int BPF_UPROBE(trace_abi_uprobe__ZdaPv, void *address) { return gen_free_enter(ctx, op_delete, (u64)address); }
SEC("uprobe/libc++abi:_ZdaPvSt11align_val_t")
int BPF_UPROBE(trace_abi_uprobe__ZdaPvSt11align_val_t, void *address) { return gen_free_enter(ctx, op_delete, (u64)address); }
SEC("uprobe/libc++abi:_ZdaPvm")
int BPF_UPROBE(trace_abi_uprobe__ZdaPvm, void *address) { return gen_free_enter(ctx, op_delete, (u64)address); }
SEC("uprobe/libc++abi:_ZdlPv")
int BPF_UPROBE(trace_abi_uprobe__ZdlPv, void *address) { return gen_free_enter(ctx, op_delete, (u64)address); }
SEC("uprobe/libc++abi:_ZdlPvSt11align_val_t")
int BPF_UPROBE(trace_abi_uprobe__ZdlPvSt11align_val_t, void *address) { return gen_free_enter(ctx, op_delete, (u64)address); }
SEC("uprobe/libc++abi:_ZdlPvm")
int BPF_UPROBE(trace_abi_uprobe__ZdlPvm, void *address) { return gen_free_enter(ctx, op_delete, (u64)address); }
SEC("uprobe/libc++abi:_Znam")
int BPF_UPROBE(trace_abi_uprobe__Znam, size_t size) { return gen_cxx_array_alloc_enter(size); }
SEC("uprobe/libc++abi:_ZnamRKSt9nothrow_t")
int BPF_UPROBE(trace_abi_uprobe__ZnamRKSt9nothrow_t, size_t size) { return gen_cxx_array_alloc_enter(size); }
SEC("uprobe/libc++abi:_ZnamSt11align_val_t")
int BPF_UPROBE(trace_abi_uprobe__ZnamSt11align_val_t, size_t size) { return gen_cxx_array_alloc_enter(size); }
SEC("uprobe/libc++abi:_Znwm")
int BPF_UPROBE(trace_abi_uprobe__Znwm, size_t size) { return gen_cxx_alloc_enter(size); }
SEC("uprobe/libc++abi:_ZnwmRKSt9nothrow_t")
int BPF_UPROBE(trace_abi_uprobe__ZnwmRKSt9nothrow_t, size_t size) { return gen_cxx_alloc_enter(size); }
SEC("uprobe/libc++abi:_ZnwmSt11align_val_t")
int BPF_UPROBE(trace_abi_uprobe__ZnwmSt11align_val_t, size_t size) { return gen_cxx_alloc_enter(size); }
SEC("uretprobe/libc++abi:_Znam")
int trace_abi_uretprobe__Znam(struct pt_regs *ctx) { return gen_cxx_array_alloc_exit(ctx, op_new_array, PT_REGS_RC(ctx)); }
SEC("uretprobe/libc++abi:_ZnamRKSt9nothrow_t")
int trace_abi_uretprobe__ZnamRKSt9nothrow_t(struct pt_regs *ctx) { return gen_cxx_array_alloc_exit(ctx, op_new_array, PT_REGS_RC(ctx)); }
SEC("uretprobe/libc++abi:_ZnamSt11align_val_t")
int trace_abi_uretprobe__ZnamSt11align_val_t(struct pt_regs *ctx) { return gen_cxx_array_alloc_exit(ctx, op_new_array, PT_REGS_RC(ctx)); }
SEC("uretprobe/libc++abi:_Znwm")
int trace_abi_uretprobe__Znwm(struct pt_regs *ctx) { return gen_cxx_alloc_exit(ctx, op_new, PT_REGS_RC(ctx)); }
SEC("uretprobe/libc++abi:_ZnwmRKSt9nothrow_t")
int trace_abi_uretprobe__ZnwmRKSt9nothrow_t(struct pt_regs *ctx) { return gen_cxx_alloc_exit(ctx, op_new, PT_REGS_RC(ctx)); }
SEC("uretprobe/libc++abi:_ZnwmSt11align_val_t")
int trace_abi_uretprobe__ZnwmSt11align_val_t(struct pt_regs *ctx) { return gen_cxx_alloc_exit(ctx, op_new, PT_REGS_RC(ctx)); }

char LICENSE[] SEC("license") = "Dual BSD/GPL";
