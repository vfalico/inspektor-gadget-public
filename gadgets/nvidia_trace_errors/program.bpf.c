// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2026 The Inspektor Gadget authors

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <gadget/buffer.h>
#include <gadget/common.h>
#include <gadget/types.h>
#include <gadget/macros.h>
#include <gadget/user_stack_map.h>

#define MAX_ENTRIES 16384

/* Event source discriminator */
enum error_source {
	SOURCE_CUDA_API = 1,
	SOURCE_XID      = 2,
};

/* CUDA_SUCCESS — the only return we do NOT record */
#define CUDA_SUCCESS 0

/*
 * API IDs — stable identifiers for each hooked libcuda function.
 * Kept as #define (not enum) so they match the WASM catalog's uint32 keys
 * directly without sign-extension ambiguity.
 */
#define API_cuMemAlloc_v2         1
#define API_cuMemAllocPitch_v2    2
#define API_cuMemAllocManaged     3
#define API_cuLaunchKernel        4
#define API_cuCtxCreate_v2        5
#define API_cuDeviceGet           6
#define API_cuDeviceGetCount      7
#define API_cuModuleLoad          8
#define API_cuModuleLoadData      9
#define API_cuModuleGetFunction  10
#define API_cuMemcpyHtoD_v2      11
#define API_cuMemcpyDtoH_v2      12
#define API_cuStreamCreate       13
#define API_cuStreamQuery        14
#define API_cuStreamSynchronize  15
#define API_cuEventCreate        16
#define API_cuEventRecord        17
#define API_cuEventQuery         18
#define API_cuEventSynchronize   19
#define API_cuMemFree_v2         20
#define API_cuCtxSynchronize     21
#define API_cuInit               22

struct event {
	gadget_timestamp timestamp_raw;
	struct gadget_process proc;

	__u32 source_raw;      /* enum error_source */

	__s32 error_code_raw;  /* CUresult; 0 for XID */
	__u32 api_id_raw;      /* API_*; 0 for XID */

	__u32 xid_code;
	__u32 pci_domain;
	__u8  pci_bus;
	__u8  pci_slot;
	__u8  pci_func;
	__u8  _pad;

	__u64 arg1;
	__u64 arg2;
	__u64 arg3;
	__u64 arg4;
	__u64 arg5;
	__u64 arg6;

	struct gadget_user_stack ustack_raw;
};

/* Per-TID stash so uretprobe can emit the args captured at entry. */
struct entry_args {
	__u32 api_id;
	__u64 arg1;
	__u64 arg2;
	__u64 arg3;
	__u64 arg4;
	__u64 arg5;
	__u64 arg6;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u64);               /* bpf_get_current_pid_tgid() */
	__type(value, struct entry_args);
} entries SEC(".maps");

GADGET_TRACER_MAP(events, 1024 * 512);
GADGET_TRACER(nvidia_errors, events, event);

static __always_inline int
save_entry(__u32 api_id,
	   __u64 a1, __u64 a2, __u64 a3,
	   __u64 a4, __u64 a5, __u64 a6)
{
	__u64 tid = bpf_get_current_pid_tgid();
	struct entry_args args = {
		.api_id = api_id,
		.arg1   = a1, .arg2 = a2, .arg3 = a3,
		.arg4   = a4, .arg5 = a5, .arg6 = a6,
	};
	bpf_map_update_elem(&entries, &tid, &args, BPF_ANY);
	return 0;
}

static __always_inline int
handle_return(struct pt_regs *ctx)
{
	__u64 tid = bpf_get_current_pid_tgid();
	struct entry_args *args = bpf_map_lookup_elem(&entries, &tid);
	if (!args)
		return 0;

	__s32 ret = (__s32)PT_REGS_RC(ctx);
	if (ret == CUDA_SUCCESS) {
		bpf_map_delete_elem(&entries, &tid);
		return 0;
	}

	struct event *e = gadget_reserve_buf(&events, sizeof(*e));
	if (!e) {
		bpf_map_delete_elem(&entries, &tid);
		return 0;
	}

	e->timestamp_raw  = bpf_ktime_get_boot_ns();
	gadget_process_populate(&e->proc);

	e->source_raw     = SOURCE_CUDA_API;
	e->error_code_raw = ret;
	e->api_id_raw     = args->api_id;
	e->arg1 = args->arg1;
	e->arg2 = args->arg2;
	e->arg3 = args->arg3;
	e->arg4 = args->arg4;
	e->arg5 = args->arg5;
	e->arg6 = args->arg6;

	gadget_get_user_stack(ctx, &e->ustack_raw);
	gadget_submit_buf(ctx, &events, e, sizeof(*e));
	bpf_map_delete_elem(&entries, &tid);
	return 0;
}

/* ─── XID kprobe ──────────────────────────────────────────────────────────
 * nv_report_error is exported by the NVIDIA kernel module (open-source build).
 * Signature: void nv_report_error(struct pci_dev *dev, NvU32 error_number,
 *                                 const char *format, va_list ap);
 * We only read the first two args.
 */
SEC("kprobe/nv_report_error")
int BPF_KPROBE(trace_nv_report_error, struct pci_dev *dev, __u32 error_number)
{
	struct event *e = gadget_reserve_buf(&events, sizeof(*e));
	if (!e)
		return 0;

	e->timestamp_raw = bpf_ktime_get_boot_ns();
	gadget_process_populate(&e->proc);

	e->source_raw = SOURCE_XID;
	e->xid_code   = error_number;

	if (dev) {
		e->pci_bus    = BPF_CORE_READ(dev, bus, number);
		__u32 devfn   = BPF_CORE_READ(dev, devfn);
		e->pci_slot   = devfn >> 3;
		e->pci_func   = devfn & 0x7;
		e->pci_domain = 0;
	}

	gadget_submit_buf(ctx, &events, e, sizeof(*e));
	return 0;
}

/* ─── libcuda uprobes (22 entry/return pairs) ───────────────────────────── */

SEC("uprobe/libcuda:cuInit")
int BPF_UPROBE(probe_cuInit_entry, unsigned int flags)
{ return save_entry(API_cuInit, flags, 0, 0, 0, 0, 0); }
SEC("uretprobe/libcuda:cuInit")
int BPF_URETPROBE(probe_cuInit_return) { return handle_return(ctx); }

SEC("uprobe/libcuda:cuDeviceGet")
int BPF_UPROBE(probe_cuDeviceGet_entry, void *device, int ordinal)
{ return save_entry(API_cuDeviceGet, (__u64)(unsigned long)device, ordinal,
		    0, 0, 0, 0); }
SEC("uretprobe/libcuda:cuDeviceGet")
int BPF_URETPROBE(probe_cuDeviceGet_return) { return handle_return(ctx); }

SEC("uprobe/libcuda:cuDeviceGetCount")
int BPF_UPROBE(probe_cuDeviceGetCount_entry, void *count)
{ return save_entry(API_cuDeviceGetCount, (__u64)(unsigned long)count,
		    0, 0, 0, 0, 0); }
SEC("uretprobe/libcuda:cuDeviceGetCount")
int BPF_URETPROBE(probe_cuDeviceGetCount_return) { return handle_return(ctx); }

SEC("uprobe/libcuda:cuCtxCreate_v2")
int BPF_UPROBE(probe_cuCtxCreate_entry, void *pctx, unsigned int flags, int dev)
{ return save_entry(API_cuCtxCreate_v2, (__u64)(unsigned long)pctx, flags,
		    dev, 0, 0, 0); }
SEC("uretprobe/libcuda:cuCtxCreate_v2")
int BPF_URETPROBE(probe_cuCtxCreate_return) { return handle_return(ctx); }

SEC("uprobe/libcuda:cuCtxSynchronize")
int BPF_UPROBE(probe_cuCtxSynchronize_entry)
{ return save_entry(API_cuCtxSynchronize, 0, 0, 0, 0, 0, 0); }
SEC("uretprobe/libcuda:cuCtxSynchronize")
int BPF_URETPROBE(probe_cuCtxSynchronize_return) { return handle_return(ctx); }

SEC("uprobe/libcuda:cuMemAlloc_v2")
int BPF_UPROBE(probe_cuMemAlloc_entry, void *dptr, __u64 bytesize)
{ return save_entry(API_cuMemAlloc_v2, (__u64)(unsigned long)dptr, bytesize,
		    0, 0, 0, 0); }
SEC("uretprobe/libcuda:cuMemAlloc_v2")
int BPF_URETPROBE(probe_cuMemAlloc_return) { return handle_return(ctx); }

SEC("uprobe/libcuda:cuMemAllocPitch_v2")
int BPF_UPROBE(probe_cuMemAllocPitch_entry, void *dptr, void *pitch,
	       __u64 width, __u64 height, unsigned int element_size)
{ return save_entry(API_cuMemAllocPitch_v2,
		    (__u64)(unsigned long)dptr,
		    (__u64)(unsigned long)pitch,
		    width, height, element_size, 0); }
SEC("uretprobe/libcuda:cuMemAllocPitch_v2")
int BPF_URETPROBE(probe_cuMemAllocPitch_return) { return handle_return(ctx); }

SEC("uprobe/libcuda:cuMemAllocManaged")
int BPF_UPROBE(probe_cuMemAllocManaged_entry, void *dptr, __u64 bytesize,
	       unsigned int flags)
{ return save_entry(API_cuMemAllocManaged, (__u64)(unsigned long)dptr,
		    bytesize, flags, 0, 0, 0); }
SEC("uretprobe/libcuda:cuMemAllocManaged")
int BPF_URETPROBE(probe_cuMemAllocManaged_return) { return handle_return(ctx); }

SEC("uprobe/libcuda:cuMemFree_v2")
int BPF_UPROBE(probe_cuMemFree_entry, __u64 dptr)
{ return save_entry(API_cuMemFree_v2, dptr, 0, 0, 0, 0, 0); }
SEC("uretprobe/libcuda:cuMemFree_v2")
int BPF_URETPROBE(probe_cuMemFree_return) { return handle_return(ctx); }

SEC("uprobe/libcuda:cuMemcpyHtoD_v2")
int BPF_UPROBE(probe_cuMemcpyHtoD_entry, __u64 dst, const void *src, __u64 bytes)
{ return save_entry(API_cuMemcpyHtoD_v2, dst,
		    (__u64)(unsigned long)src, bytes, 0, 0, 0); }
SEC("uretprobe/libcuda:cuMemcpyHtoD_v2")
int BPF_URETPROBE(probe_cuMemcpyHtoD_return) { return handle_return(ctx); }

SEC("uprobe/libcuda:cuMemcpyDtoH_v2")
int BPF_UPROBE(probe_cuMemcpyDtoH_entry, void *dst, __u64 src, __u64 bytes)
{ return save_entry(API_cuMemcpyDtoH_v2,
		    (__u64)(unsigned long)dst, src, bytes, 0, 0, 0); }
SEC("uretprobe/libcuda:cuMemcpyDtoH_v2")
int BPF_URETPROBE(probe_cuMemcpyDtoH_return) { return handle_return(ctx); }

SEC("uprobe/libcuda:cuModuleLoad")
int BPF_UPROBE(probe_cuModuleLoad_entry, void *module, const char *fname)
{ return save_entry(API_cuModuleLoad,
		    (__u64)(unsigned long)module,
		    (__u64)(unsigned long)fname,
		    0, 0, 0, 0); }
SEC("uretprobe/libcuda:cuModuleLoad")
int BPF_URETPROBE(probe_cuModuleLoad_return) { return handle_return(ctx); }

SEC("uprobe/libcuda:cuModuleLoadData")
int BPF_UPROBE(probe_cuModuleLoadData_entry, void *module, const void *image)
{ return save_entry(API_cuModuleLoadData,
		    (__u64)(unsigned long)module,
		    (__u64)(unsigned long)image,
		    0, 0, 0, 0); }
SEC("uretprobe/libcuda:cuModuleLoadData")
int BPF_URETPROBE(probe_cuModuleLoadData_return) { return handle_return(ctx); }

SEC("uprobe/libcuda:cuModuleGetFunction")
int BPF_UPROBE(probe_cuModuleGetFunction_entry, void *hfunc, void *hmod,
	       const char *name)
{ return save_entry(API_cuModuleGetFunction,
		    (__u64)(unsigned long)hfunc,
		    (__u64)(unsigned long)hmod,
		    (__u64)(unsigned long)name,
		    0, 0, 0); }
SEC("uretprobe/libcuda:cuModuleGetFunction")
int BPF_URETPROBE(probe_cuModuleGetFunction_return) { return handle_return(ctx); }

SEC("uprobe/libcuda:cuLaunchKernel")
int BPF_UPROBE(probe_cuLaunchKernel_entry,
	       void *f,
	       unsigned int gridX, unsigned int gridY, unsigned int gridZ,
	       unsigned int blockX, unsigned int blockY)
{ return save_entry(API_cuLaunchKernel,
		    (__u64)(unsigned long)f,
		    gridX, gridY, gridZ, blockX, blockY); }
SEC("uretprobe/libcuda:cuLaunchKernel")
int BPF_URETPROBE(probe_cuLaunchKernel_return) { return handle_return(ctx); }

SEC("uprobe/libcuda:cuStreamCreate")
int BPF_UPROBE(probe_cuStreamCreate_entry, void *phstream, unsigned int flags)
{ return save_entry(API_cuStreamCreate,
		    (__u64)(unsigned long)phstream, flags, 0, 0, 0, 0); }
SEC("uretprobe/libcuda:cuStreamCreate")
int BPF_URETPROBE(probe_cuStreamCreate_return) { return handle_return(ctx); }

SEC("uprobe/libcuda:cuStreamQuery")
int BPF_UPROBE(probe_cuStreamQuery_entry, void *hstream)
{ return save_entry(API_cuStreamQuery,
		    (__u64)(unsigned long)hstream, 0, 0, 0, 0, 0); }
SEC("uretprobe/libcuda:cuStreamQuery")
int BPF_URETPROBE(probe_cuStreamQuery_return) { return handle_return(ctx); }

SEC("uprobe/libcuda:cuStreamSynchronize")
int BPF_UPROBE(probe_cuStreamSynchronize_entry, void *hstream)
{ return save_entry(API_cuStreamSynchronize,
		    (__u64)(unsigned long)hstream, 0, 0, 0, 0, 0); }
SEC("uretprobe/libcuda:cuStreamSynchronize")
int BPF_URETPROBE(probe_cuStreamSynchronize_return) { return handle_return(ctx); }

SEC("uprobe/libcuda:cuEventCreate")
int BPF_UPROBE(probe_cuEventCreate_entry, void *phevent, unsigned int flags)
{ return save_entry(API_cuEventCreate,
		    (__u64)(unsigned long)phevent, flags, 0, 0, 0, 0); }
SEC("uretprobe/libcuda:cuEventCreate")
int BPF_URETPROBE(probe_cuEventCreate_return) { return handle_return(ctx); }

SEC("uprobe/libcuda:cuEventRecord")
int BPF_UPROBE(probe_cuEventRecord_entry, void *hevent, void *hstream)
{ return save_entry(API_cuEventRecord,
		    (__u64)(unsigned long)hevent,
		    (__u64)(unsigned long)hstream,
		    0, 0, 0, 0); }
SEC("uretprobe/libcuda:cuEventRecord")
int BPF_URETPROBE(probe_cuEventRecord_return) { return handle_return(ctx); }

SEC("uprobe/libcuda:cuEventQuery")
int BPF_UPROBE(probe_cuEventQuery_entry, void *hevent)
{ return save_entry(API_cuEventQuery,
		    (__u64)(unsigned long)hevent, 0, 0, 0, 0, 0); }
SEC("uretprobe/libcuda:cuEventQuery")
int BPF_URETPROBE(probe_cuEventQuery_return) { return handle_return(ctx); }

SEC("uprobe/libcuda:cuEventSynchronize")
int BPF_UPROBE(probe_cuEventSynchronize_entry, void *hevent)
{ return save_entry(API_cuEventSynchronize,
		    (__u64)(unsigned long)hevent, 0, 0, 0, 0, 0); }
SEC("uretprobe/libcuda:cuEventSynchronize")
int BPF_URETPROBE(probe_cuEventSynchronize_return) { return handle_return(ctx); }

char LICENSE[] SEC("license") = "GPL";
