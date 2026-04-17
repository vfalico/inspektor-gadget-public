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

/*
 * Event source discriminator. A single datasource delivers both CUDA API
 * errors (observed in user-space via uprobes on libcuda.so) and NVIDIA
 * XID events (observed in the kernel via a kprobe on nv_report_error).
 */
enum error_source {
	SOURCE_CUDA_API = 1,
	SOURCE_XID      = 2,
};

/*
 * event is emitted via gadget_submit_buf() to the "events" ringbuf for both
 * sources. Fields not relevant to a given source are left zero-initialised.
 */
struct event {
	gadget_timestamp timestamp_raw;
	struct gadget_process proc;

	__u32 source_raw;      /* enum error_source */

	__s32 error_code_raw;  /* CUDA CUresult; 0 for XID */
	__u32 api_id_raw;      /* API_* id from patch 0002; 0 for XID */

	__u32 xid_code;        /* 0 for CUDA API events */
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

GADGET_TRACER_MAP(events, 1024 * 512);
GADGET_TRACER(nvidia_errors, events, event);

char LICENSE[] SEC("license") = "GPL";
