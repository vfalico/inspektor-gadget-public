// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 The Inspektor Gadget authors

// WASM control plane for mcp_ebpf_proxy — a single multi-capability gadget.
//
// The agent picks a `capability`; gadgetPreStart() enables only that
// capability's eBPF programs (rewriting programs.<name>.attach_to to the chosen
// kernel symbol for `attach`, or leaving the SEC-default target for the
// tracepoint/iter capabilities) and disables every other program with the
// gadget_program_disabled sentinel. For `trace_syscall` it also resolves the
// agent's syscall name -> id and populates the (pid, syscall) BPF filter maps,
// because gadgetPreStart runs AFTER the eBPF object is loaded (rodata frozen),
// so the runtime values travel through maps rather than const-volatile globals.
//
//	capability = attach          -> mep_kprobe / mep_kretprobe (retargeted)
//	capability = attach_uprobe   -> mep_uprobe / mep_uretprobe (retargeted to path:sym)
//	capability = trace_syscall   -> mep_sys_enter / mep_sys_exit + filter maps
//	capability = cuda_memtrace   -> CUDA driver+runtime alloc/free uprobes
//	capability = list_attachable -> mep_ksym (iter/ksym), name/type via rodata
//
// READ-ONLY control plane: it only validates input, sets config, populates
// filter maps and stamps output columns. It performs no host-FS or network IO.
package main

import (
	"strconv"
	"strings"

	api "github.com/inspektor-gadget/inspektor-gadget/wasmapi/go"
)

const disabled = "gadget_program_disabled"

// maxFuncLen bounds the agent-supplied symbol name.
const maxFuncLen = 128

// maxUprobeTargetLen bounds the agent-supplied "<lib-or-path>:<symbol>" target.
const maxUprobeTargetLen = 384

// eBPF program section names (must match SEC()/func names in program.bpf.c).
const (
	progKprobe    = "mep_kprobe"
	progKretprobe = "mep_kretprobe"
	progSysEnter  = "mep_sys_enter"
	progSysExit   = "mep_sys_exit"
	progKsym      = "mep_ksym"

	// attach_uprobe: generic retargetable userspace uprobe/uretprobe.
	progUprobe    = "mep_uprobe"
	progUretprobe = "mep_uretprobe"
)

// cudaPrograms are the fixed CUDA alloc/free uprobes for the cuda_memtrace
// capability. Each keeps its SEC-default "libcuda:"/"libcudart:" attach target
// (resolved by IG's uprobetracer via the target process ld.so.cache), so they
// are enabled with "" (no attach_to rewrite) — exactly like the tracepoints.
var cudaPrograms = []string{
	"mep_cu_alloc", "mep_cu_alloc_ret",
	"mep_cu_alloc_async", "mep_cu_alloc_async_ret",
	"mep_cu_free", "mep_cu_free_ret",
	"mep_cu_free_async", "mep_cu_free_async_ret",
	"mep_cudart_alloc", "mep_cudart_alloc_ret",
	"mep_cudart_alloc_async", "mep_cudart_alloc_async_ret",
	"mep_cudart_free", "mep_cudart_free_ret",
	"mep_cudart_free_async", "mep_cudart_free_async_ret",
}

// memsnapPrograms are the NVML per-PID standing-residency uprobes for the
// cuda_memsnapshot capability. Unlike the event-delta CUDA family they are
// RETARGETED to an absolute libnvidia-ml.so.1 path at preStart, because the
// "libnvidia-ml.so.1" base-name does not resolve via the traced process
// ld.so.cache for IG's uprobetracer (verified: base-name=0 hits, abs=hits).
var memsnapPrograms = []string{
	"mep_memsnap_procs_enter", "mep_memsnap_procs_ret",
	"mep_memsnap_dev_enter", "mep_memsnap_dev_ret",
}

// smutilPrograms are the NVML per-PID SM/compute-utilization uprobes for the
// cuda_smutil capability. Like memsnapPrograms they are RETARGETED to the
// absolute libnvidia-ml.so.1 path at preStart (base-name does not resolve).
var smutilPrograms = []string{
	"mep_smutil_enter", "mep_smutil_ret",
}

// ---------------------------------------------------------------------------
// Enriched "swiss-army" capability families. Each is a fixed set of programs
// that keep their SEC-default attach target (uprobe lib:sym, kprobe symbol,
// tracepoint, or tp_btf) — so, exactly like cudaPrograms, they are enabled with
// "" (no attach_to rewrite) and every other program gets the disable sentinel.
// ---------------------------------------------------------------------------

// cuda_profile: GPU activity (launch dims, sync duration, H2D/D2H bytes).
var cudaProfilePrograms = []string{
	"mep_cuprof_launch", "mep_cuprof_launch_ex",
	"mep_cuprof_streamsync", "mep_cuprof_streamsync_ret",
	"mep_cuprof_ctxsync", "mep_cuprof_ctxsync_ret",
	"mep_cuprof_h2d", "mep_cuprof_h2d_async",
	"mep_cuprof_d2h", "mep_cuprof_d2h_async",
}

// lock_trace: userspace mutex/cond contention (blocked-wait duration).
var lockTracePrograms = []string{
	"mep_lock_mutex", "mep_lock_mutex_ret",
	"mep_lock_cond", "mep_lock_cond_ret",
	"mep_lock_condt", "mep_lock_condt_ret",
	"mep_lock_futex_enter", "mep_lock_futex_exit", // directive-22126: kernel futex(WAIT) contention hook
}

// heap_profile: libc allocator churn/leak (malloc/calloc/realloc/free).
var heapProfilePrograms = []string{
	"mep_heap_malloc", "mep_heap_malloc_ret",
	"mep_heap_calloc", "mep_heap_calloc_ret",
	"mep_heap_realloc", "mep_heap_realloc_ret",
	"mep_heap_free",
	// host-visible kernel tracepoints (libc uprobes are container-scoped and
	// miss host workloads — these capture brk()/anon-mmap heap growth in the
	// target's own process context, attributed via the shared filter_pid gate).
	"mep_heap_brk", "mep_heap_mmap",
}

// net_trace: networking (tcp connect 4-tuple+errno, retransmit, sendmsg bytes).
var netTracePrograms = []string{
	"mep_net_connect", "mep_net_connect_ret",
	"mep_net_retransmit", "mep_net_sendmsg",
}

// fs_trace: filesystem (vfs_read/write byte counts, vfs_open result).
var fsTracePrograms = []string{
	"mep_fs_read", "mep_fs_read_ret",
	"mep_fs_write", "mep_fs_write_ret",
	"mep_fs_open", "mep_fs_open_ret",
	"mep_fs_filp_open", "mep_fs_filp_open_ret",
}

// mm_trace: memory management (page faults + direct-reclaim duration).
var mmTracePrograms = []string{
	"mep_mm_fault",
	"mep_mm_reclaim", "mep_mm_reclaim_ret",
}

// irq_trace: drivers/IRQ (softirq entry->exit service duration per vector).
var irqTracePrograms = []string{
	"mep_irq_entry", "mep_irq_exit",
}

// block_io: block layer (per-request dev/sector/bytes/rw + issue->done latency).
var blockIoPrograms = []string{
	"mep_blk_start", "mep_blk_done",
}

// runq_lat: scheduler (run-queue wait: enqueue -> on-cpu latency).
var runqLatPrograms = []string{
	"mep_runq_enqueue", "mep_runq_switch",
}

// enrichedFamilies groups the new fixed-program capabilities for allPrograms
// assembly and the capability dispatch table.
var enrichedFamilies = [][]string{
	cudaProfilePrograms, lockTracePrograms, heapProfilePrograms,
	netTracePrograms, fsTracePrograms, mmTracePrograms,
	irqTracePrograms, blockIoPrograms, runqLatPrograms,
}

// every program in the object; any not enabled by the chosen capability is
// disabled with the sentinel.
var allPrograms = append([]string{
	progKprobe, progKretprobe, progSysEnter, progSysExit, progKsym,
	progUprobe, progUretprobe,
}, cudaPrograms...)

// extend allPrograms with every enriched-family program so that whichever
// capability runs, all the others are disabled with the sentinel.
func init() {
	for _, fam := range enrichedFamilies {
		allPrograms = append(allPrograms, fam...)
	}
}

// attach mode -> kprobe programs that should attach to `function`.
var modePrograms = map[string][]string{
	"kprobe":           {progKprobe},
	"kretprobe":        {progKretprobe},
	"kprobe_kretprobe": {progKprobe, progKretprobe},
}

// uprobeModePrograms maps the attach_uprobe `mode` to the uprobe programs that
// should be retargeted to the agent-supplied target.
var uprobeModePrograms = map[string][]string{
	"uprobe":           {progUprobe},
	"uretprobe":        {progUretprobe},
	"uprobe_uretprobe": {progUprobe, progUretprobe},
}

var futureModes = map[string]bool{
	"fentry": true, "fexit": true, "fentry_fexit": true,
}

// anySyscall is the "trace every syscall" sentinel mirrored in program.bpf.c.
const anySyscall uint64 = 0xffffffff

// validatedFunc is remembered between gadgetPreStart and gadgetInit so the
// `attach` enricher can stamp the resolved symbol onto every event.
var validatedFunc string

// --- attach-confirmation / coverage feedback --------------------------
//
// A capability's PreStart records WHAT it attached here, and gadgetStart emits a
// single mep_coverage record so the agent can distinguish "attached but the
// workload produced no events" from "attach failed / wrong target". Without this
// an empty result is ambiguous and the model burns RCA cycles re-trying.
var (
	covCapability string   // selected capability
	covTargets    []string // attach targets actually programmed
	covProgCount  int      // number of eBPF programs enabled
	covPidFilter  uint64   // resolved pid filter (0 == all pids)
	covNote       string   // capability-specific interpretation hint
)

// recordCoverage is called at the end of each successful PreStart path to
// capture what was attached, for the one-time mep_coverage emit in gadgetStart.
func recordCoverage(capability string, targets []string, progCount int, pid uint64, note string) {
	covCapability = capability
	covTargets = targets
	covProgCount = progCount
	covPidFilter = pid
	covNote = note
}

// coverageDS is the mep_coverage datasource handle, created in gadgetInit and
// emitted once in gadgetStart. Zero value means "not registered" (we skip emit).
var (
	coverageDS      api.DataSource
	coverageReady   bool
	covFieldCap     api.Field
	covFieldTargets api.Field
	covFieldCount   api.Field
	covFieldPid     api.Field
	covFieldNote    api.Field
)

// emitCoverageRecord publishes the single coverage record. Safe to call even if
// the datasource was not registered (no-op then).
func emitCoverageRecord() {
	if !coverageReady || covCapability == "" {
		// covCapability is only set by the instrumented enriched/GPU PreStart
		// paths. The explicit-target paths (attach/attach_uprobe/trace_syscall/
		// list_attachable) are unambiguous, so we skip a coverage record there
		// rather than emit a misleading empty one.
		return
	}
	pkt, err := coverageDS.NewPacketSingle()
	if err != nil {
		return
	}
	d := api.Data(pkt)
	covFieldCap.SetString(d, covCapability)
	covFieldTargets.SetString(d, strings.Join(covTargets, ","))
	covFieldCount.SetUint32(d, uint32(covProgCount))
	covFieldPid.SetUint64(d, covPidFilter)
	covFieldNote.SetString(d, covNote)
	coverageDS.EmitAndRelease(api.Packet(pkt))
}

// trace_syscall filter values are resolved/validated in gadgetPreStart but
// WRITTEN to the BPF maps in gadgetStart: the ebpf operator only exposes maps
// to WASM (SetVar(MapPrefix+name)) inside its Start() stage, which runs AFTER
// the wasm operator's PreStart(). Calling GetMap() from gadgetPreStart() fails
// with "no map for name". traceloop's gadget reads its maps from gadgetStart()
// for exactly this reason; mirror that ordering here.
var (
	tsActive    bool   // true once trace_syscall PreStart succeeded
	tsFilterNr  uint64 // syscall number, or anySyscall
	tsFilterPid uint64 // pid, or 0 == any

	// Enriched swiss-army families share the SAME filter_pid map as
	// trace_syscall but do NOT use filter_syscall/enabled. enrichedActive is
	// set by preStartFixed/preStartCudaMemtrace when the agent passes a pid, so
	// gadgetStart knows to publish filter_pid for them too.
	enrichedActive    bool
	enrichedFilterPid uint64 // pid, or 0 == any

	// fs_trace-only server-side op filter. Published into
	// the filter_fs_op BPF map in gadgetStart so the rare failing-open rows are
	// not truncated out of the MCP window by the vfs_read/write flood. 0 == all.
	enrichedFsOp uint64

	// cuda_profile-only server-side op-class filter.
	// Published into the filter_cuda_op BPF map in gadgetStart so the rare
	// memcpy_h2d/d2h rows (the PCIe copy-bottleneck signal) are not truncated
	// out of the MCP window by the high-rate cuLaunchKernel stream. 0 == all.
	enrichedCudaOp uint64
)

// fsOpFilterValue maps the optional `fs_op` MCP param to the in-kernel
// filter_fs_op selector (see FS_FILTER_* in program.bpf.c). Empty/"all" keeps
// every op; "fault" keeps only ops that returned an error (the failing-open
// case); read/write/open/filp_open/close keep that single class. Unknown => error.
func fsOpFilterValue() (uint64, bool) {
	v, err := api.GetParamValue("fs_op", 32)
	if err != nil {
		api.Errorf("mcp_ebpf_proxy[fs_trace]: reading fs_op param: %s", err)
		return 0, false
	}
	switch v {
	case "", "all":
		return 0, true // FS_FILTER_ALL
	case "read":
		return 1, true
	case "write":
		return 2, true
	case "open":
		return 3, true
	case "filp_open", "failing_open", "filp":
		return 4, true
	case "fault", "error", "failed":
		return 5, true
	case "close", "release", "filp_close":
		return 6, true // FS_FILTER_CLOSE — the filp_close release side; pair with open for fd-leak balance
	default:
		api.Errorf("mcp_ebpf_proxy[fs_trace]: invalid fs_op %q; choose one of all, read, write, open, filp_open, fault, close. Use fs_op=fault (or filp_open) to isolate failing opens (e.g. openat -> ENOENT) without the high-volume read/write noise; use fs_op=close to isolate the filp_close releases for an open-minus-close fd-leak balance", v)
		return 0, false
	}
}

// cudaOpFilterValue maps the optional `cuda_op` MCP param to the in-kernel
// filter_cuda_op selector (see CUDA_OP_FILTER_* in program.bpf.c). Empty/"all"
// keeps every GPU op class; "copy" keeps only the memcpy_h2d+memcpy_d2h rows
// that carry the PCIe transfer byte volume; h2d/d2h narrow to one direction;
// launch/sync keep that single class. Unknown => error. This lets the agent
// isolate the PCIe copy signal from the cuLaunchKernel flood that would
// otherwise truncate it out of the MCP result (mirror of the fs_op fix).
func cudaOpFilterValue() (uint64, bool) {
	v, err := api.GetParamValue("cuda_op", 32)
	if err != nil {
		api.Errorf("mcp_ebpf_proxy[cuda_profile]: reading cuda_op param: %s", err)
		return 0, false
	}
	switch v {
	case "", "all":
		return 0, true // CUDA_OP_FILTER_ALL
	case "launch", "kernel":
		return 1, true
	case "sync", "synchronize":
		return 2, true
	case "copy", "memcpy", "transfer", "pcie":
		return 3, true
	case "h2d", "htod", "host_to_device":
		return 4, true
	case "d2h", "dtoh", "device_to_host":
		return 5, true
	default:
		api.Errorf("mcp_ebpf_proxy[cuda_profile]: invalid cuda_op %q; choose one of all, launch, sync, copy, h2d, d2h. Use cuda_op=copy (or h2d) to isolate the PCIe host<->device transfer rows — which carry the byte volume proving a copy/PCIe bottleneck — from the high-rate cuLaunchKernel stream that would otherwise truncate them out of the result", v)
		return 0, false
	}
}

// readPidParam parses the optional `pid` MCP param (shared by trace_syscall and
// every enriched family). Empty => 0 (all processes). Returns (pid, ok).
func readPidParam(tag string) (uint64, bool) {
	pidStr, err := api.GetParamValue("pid", 32)
	if err != nil {
		api.Errorf("mcp_ebpf_proxy[%s]: reading pid param: %s", tag, err)
		return 0, false
	}
	if pidStr == "" {
		return 0, true
	}
	pv, err := strconv.ParseUint(pidStr, 10, 32)
	if err != nil {
		api.Errorf("mcp_ebpf_proxy[%s]: invalid pid %q (must be a non-negative integer)", tag, pidStr)
		return 0, false
	}
	return pv, true
}

// validLibChar allows the characters that can appear in a library base-name or
// an absolute .so path (letters, digits, and the path/version punctuation
// "._-+/"), rejecting NUL, whitespace, ":" and shell metacharacters.
func validLibChar(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z':
		return true
	case b >= 'A' && b <= 'Z':
		return true
	case b >= '0' && b <= '9':
		return true
	case b == '.' || b == '_' || b == '-' || b == '+' || b == '/':
		return true
	default:
		return false
	}
}

func validSymbolChar(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z':
		return true
	case b >= 'A' && b <= 'Z':
		return true
	case b >= '0' && b <= '9':
		return true
	case b == '_' || b == '.':
		return true
	default:
		return false
	}
}

// enableOnly disables every program except those named in `keep`.
func enableExact(keep map[string]string) {
	for _, p := range allPrograms {
		key := "programs." + p + ".attach_to"
		if v, ok := keep[p]; ok {
			if v != "" {
				api.SetConfig(key, v)
			}
			// v=="" means "keep the SEC-default attach target" (tracepoint/iter):
			// simply do NOT set the sentinel for it.
		} else {
			api.SetConfig(key, disabled)
		}
	}
}

//go:wasmexport gadgetPreStart
func gadgetPreStart() int32 {
	// `capability` is optional (gadget.yaml defaultValue "attach"). Local
	// `ig run` materialises that default into the param set, but over the
	// daemon/gRPC path (the real ig-mcp-server transport) a param that the
	// caller did not send is simply absent, so GetParamValue returns an error
	// rather than the default. An absent optional param must NOT be fatal:
	// fall back to the documented default instead of failing PreStart.
	capability, err := api.GetParamValue("capability", 64)
	if err != nil {
		capability = ""
	}
	if capability == "" {
		capability = "attach"
	}

	switch capability {
	case "attach":
		return preStartAttach()
	case "attach_uprobe":
		return preStartAttachUprobe()
	case "trace_syscall":
		return preStartTraceSyscall()
	case "cuda_memtrace":
		return preStartCudaMemtrace()
	case "cuda_memsnapshot":
		return preStartCudaMemsnapshot()
	case "cuda_smutil":
		return preStartCudaSmutil()
	case "cuda_profile":
		return preStartFixed("cuda_profile", cudaProfilePrograms)
	case "lock_trace":
		return preStartFixed("lock_trace", lockTracePrograms)
	case "heap_profile":
		return preStartFixed("heap_profile", heapProfilePrograms)
	case "net_trace":
		return preStartFixed("net_trace", netTracePrograms)
	case "fs_trace":
		return preStartFixed("fs_trace", fsTracePrograms)
	case "mm_trace":
		return preStartFixed("mm_trace", mmTracePrograms)
	case "irq_trace":
		return preStartFixed("irq_trace", irqTracePrograms)
	case "block_io":
		return preStartFixed("block_io", blockIoPrograms)
	case "runq_lat":
		return preStartFixed("runq_lat", runqLatPrograms)
	case "list_attachable":
		return preStartListAttachable()
	default:
		api.Errorf("mcp_ebpf_proxy: invalid capability %q; NEXT STEP: choose one of CORE{attach, attach_uprobe, trace_syscall, list_attachable} or ENRICHED{cuda_memtrace, cuda_profile, lock_trace, heap_profile, net_trace, fs_trace, mm_trace, irq_trace, block_io, runq_lat, cuda_smutil}. See capability_catalog.json for when-to-use of each", capability)
		return 1
	}
}

// ---------------------------------------------------------------- attach -----

func preStartAttach() int32 {
	function, err := api.GetParamValue("function", 256)
	if err != nil {
		api.Errorf("mcp_ebpf_proxy: reading function param: %s", err)
		return 1
	}
	if function == "" {
		api.Errorf("mcp_ebpf_proxy[attach]: the `function` param is required (a kernel symbol such as do_unlinkat); NEXT STEP: call capability=list_attachable to discover one")
		return 1
	}

	// `function` is attacker-influenced input from an AI agent over MCP and is
	// used as a kallsyms lookup key and the kprobe attach target. Constrain it
	// to the kernel-symbol grammar BEFORE either use.
	if len(function) > maxFuncLen {
		api.Errorf("mcp_ebpf_proxy[attach]: invalid function %q: longer than %d bytes", function, maxFuncLen)
		return 1
	}
	if c := function[0]; !(c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
		api.Errorf("mcp_ebpf_proxy[attach]: invalid function %q: must start with a letter or '_'", function)
		return 1
	}
	for i := 0; i < len(function); i++ {
		if !validSymbolChar(function[i]) {
			api.Errorf("mcp_ebpf_proxy[attach]: invalid function %q: char %q not allowed (use only [A-Za-z0-9_.])", function, string(function[i]))
			return 1
		}
	}

	// `mode` is optional (defaultValue "kprobe_kretprobe"). As with capability,
	// an absent param over the daemon path yields an error, not the default, so
	// treat an unreadable value as "unset" and apply the default.
	mode, err := api.GetParamValue("mode", 64)
	if err != nil {
		mode = ""
	}
	if mode == "" {
		mode = "kprobe_kretprobe"
	}
	wanted, ok := modePrograms[mode]
	if !ok {
		if futureModes[mode] {
			api.Errorf("mcp_ebpf_proxy[attach]: mode %q not yet supported; use kprobe, kretprobe or kprobe_kretprobe (fentry/fexit need BTF set_attach_target, a planned enhancement)", mode)
			return 1
		}
		api.Errorf("mcp_ebpf_proxy[attach]: invalid mode %q (want kprobe, kretprobe or kprobe_kretprobe)", mode)
		return 1
	}

	if !api.KallsymsSymbolExists(function) {
		api.Errorf("mcp_ebpf_proxy[attach]: kernel symbol %q not found in /proc/kallsyms; NEXT STEP: call capability=list_attachable (optionally filter=<name-prefix>, type=t) to enumerate valid kprobe-able symbols, then retry attach with an exact name", function)
		return 1
	}

	keep := map[string]string{}
	for _, p := range wanted {
		keep[p] = function // retarget kprobe/kretprobe to the symbol
	}
	enableExact(keep) // sys_enter/sys_exit/ksym get the sentinel

	validatedFunc = function
	api.Infof("mcp_ebpf_proxy[attach]: mode=%s attaching %d program(s) to %q", mode, len(wanted), function)
	return 0
}

// ----------------------------------------------------------- attach_uprobe ---

// preStartAttachUprobe retargets the generic uprobe/uretprobe pair to an
// arbitrary userspace symbol supplied by the agent as the `target` param in the
// form "<lib-or-abs-path>:<symbol>", e.g. "libssl:SSL_read" or
// "/usr/lib/x86_64-linux-gnu/libc.so.6:malloc". IG's uprobetracer splits on the
// first ':' (pkg/uprobetracer/tracer.go) — the left side is either an absolute
// path or a library base-name resolved through the target's ld.so.cache, the
// right side is the exported symbol. Validation here mirrors the kprobe
// `attach` path: bound the length, constrain the symbol grammar, and require a
// non-empty library/path. We deliberately do NOT stat the path or resolve the
// symbol from WASM (no host-FS access in this read-only control plane); an
// unresolved target simply fails at uprobe attach time with a clear error.
func preStartAttachUprobe() int32 {
	target, err := api.GetParamValue("target", 512)
	if err != nil {
		api.Errorf("mcp_ebpf_proxy[attach_uprobe]: reading target param: %s", err)
		return 1
	}
	if target == "" {
		api.Errorf("mcp_ebpf_proxy[attach_uprobe]: the `target` param is required, form <lib-or-path>:<symbol> (e.g. libc:malloc or /usr/lib/.../libcuda.so.1:cuMemAlloc_v2); NOTE: for CUDA prefer the enriched capability=cuda_memtrace (leaks) or capability=cuda_profile (launch/sync) which pre-wire the correct symbols")
		return 1
	}
	if len(target) > maxUprobeTargetLen {
		api.Errorf("mcp_ebpf_proxy[attach_uprobe]: invalid target %q: longer than %d bytes", target, maxUprobeTargetLen)
		return 1
	}

	// Split into library/path and symbol on the FIRST colon (an absolute path
	// never contains ':', and symbols never do either, so a single split is
	// unambiguous and matches uprobetracer's own SplitN(_, ":", 2)).
	colon := -1
	for i := 0; i < len(target); i++ {
		if target[i] == ':' {
			colon = i
			break
		}
	}
	if colon <= 0 || colon == len(target)-1 {
		api.Errorf("mcp_ebpf_proxy[attach_uprobe]: invalid target %q: expected <lib-or-path>:<symbol> with both parts non-empty", target)
		return 1
	}
	lib := target[:colon]
	symbol := target[colon+1:]

	// Symbol must be a valid C identifier-ish token (same grammar as kprobe
	// attach: [A-Za-z0-9_.], leading letter/underscore). This blocks attempts
	// to smuggle a second ':' or shell/path metacharacters into the symbol.
	if c := symbol[0]; !(c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
		api.Errorf("mcp_ebpf_proxy[attach_uprobe]: invalid symbol %q: must start with a letter or '_'", symbol)
		return 1
	}
	for i := 0; i < len(symbol); i++ {
		if !validSymbolChar(symbol[i]) {
			api.Errorf("mcp_ebpf_proxy[attach_uprobe]: invalid symbol %q: char %q not allowed (use only [A-Za-z0-9_.])", symbol, string(symbol[i]))
			return 1
		}
	}
	// The library/path side allows path characters but must not contain a NUL,
	// whitespace or shell metacharacters; it is only ever used as a dlopen-style
	// path by uprobetracer, never passed to a shell, but constrain it anyway.
	for i := 0; i < len(lib); i++ {
		if !validLibChar(lib[i]) {
			api.Errorf("mcp_ebpf_proxy[attach_uprobe]: invalid library/path %q: char %q not allowed", lib, string(lib[i]))
			return 1
		}
	}

	mode, err := api.GetParamValue("mode", 64)
	if err != nil {
		mode = ""
	}
	if mode == "" {
		mode = "uprobe_uretprobe"
	}
	wanted, ok := uprobeModePrograms[mode]
	if !ok {
		api.Errorf("mcp_ebpf_proxy[attach_uprobe]: invalid mode %q (want uprobe, uretprobe or uprobe_uretprobe)", mode)
		return 1
	}

	pid, ok := readPidParam("attach_uprobe")
	if !ok {
		return 1
	}

	keep := map[string]string{}
	for _, pr := range wanted {
		keep[pr] = target // retarget uprobe/uretprobe to "<lib>:<symbol>"
	}
	enableExact(keep)

	// host-uprobe recipe: callers use IG/MCP host mode to attach to host
	// processes. Because host mode is intentionally broad, publish the agent's
	// pid selector into filter_pid and flip enabled in gadgetStart(); the BPF
	// mep_uprobe/mep_uretprobe programs consult mep_proc_wanted() before
	// reserving/submitting an event. pid=0 keeps the legacy host-wide behavior.
	enrichedFilterPid = pid
	enrichedActive = true
	validatedFunc = symbol // stamp the symbol onto every emitted event
	api.Infof("mcp_ebpf_proxy[attach_uprobe]: mode=%s attaching %d program(s) to %q (lib=%q symbol=%q, pid filter=%d; use --host / operator.localmanager.host=true for host processes)", mode, len(wanted), target, lib, symbol, pid)
	return 0
}

// ----------------------------------------------------------- cuda_memtrace ---

// preStartCudaMemtrace enables the fixed CUDA allocator uprobe set and disables
// every other program. The CUDA probes keep their SEC-default attach targets
// ("libcuda:cuMemAlloc_v2" etc.), which IG's uprobetracer resolves against the
// traced process's loaded libraries via its ld.so.cache — so no attach_to
// rewrite is needed (enable with ""). An optional `pid` filter is accepted for
// symmetry with trace_syscall but is applied by IG's standard process filter
// (gadget.yaml), not by this control plane. The datasource is `cuda_events`.
func preStartCudaMemtrace() int32 {
	keep := map[string]string{}
	for _, pr := range cudaPrograms {
		keep[pr] = "" // keep each program's SEC-default libcuda/libcudart target
	}
	enableExact(keep)
	pid, ok := readPidParam("cuda_memtrace")
	if !ok {
		return 1
	}
	enrichedFilterPid = pid
	enrichedActive = true
	api.Infof("mcp_ebpf_proxy[cuda_memtrace]: tracing CUDA driver+runtime alloc/free (%d uprobes), pid filter=%d", len(cudaPrograms), pid)
	return 0
}

// preStartCudaMemsnapshot enables the NVML per-PID standing-residency probe
// set. It RETARGETS each program to the absolute libnvidia-ml.so.1 path
// (base-name does not resolve for this lib), so a process that reserved a
// large VRAM pool BEFORE the observation window is still visible as a
// standing gauge (used_gpu_mem per pid + device total/free/used) whenever
// any NVML consumer (nvidia-smi, dcgm-exporter) polls. Datasource:
// memsnap_events. Closes the event-delta blind spot.
func preStartCudaMemsnapshot() int32 {
	const nvml = "/lib/x86_64-linux-gnu/libnvidia-ml.so.1"
	retarget := map[string]string{
		"mep_memsnap_procs_enter": nvml + ":nvmlDeviceGetComputeRunningProcesses_v3",
		"mep_memsnap_procs_ret":   nvml + ":nvmlDeviceGetComputeRunningProcesses_v3",
		"mep_memsnap_dev_enter":   nvml + ":nvmlDeviceGetMemoryInfo_v2",
		"mep_memsnap_dev_ret":     nvml + ":nvmlDeviceGetMemoryInfo_v2",
	}
	enableExact(retarget)
	pid, ok := readPidParam("cuda_memsnapshot")
	if !ok {
		return 1
	}
	enrichedFilterPid = pid
	enrichedActive = true
	api.Infof("mcp_ebpf_proxy[cuda_memsnapshot]: standing GPU residency via NVML uprobes (%d progs) at %s, pid filter=%d", len(memsnapPrograms), nvml, pid)
	recordCoverage("cuda_memsnapshot", memsnapPrograms, len(memsnapPrograms), pid,
		"per-PID GPU residency via NVML running-process table. If gpu_pid=0 / used_gpu_mem=0 for proc rows, that is STRUCTURALLY EXPECTED in a containerized pod without an active CUDA context or with NVML PID-namespace restrictions (nvmlDeviceGetComputeRunningProcesses returns no per-proc entries) — do NOT loop re-querying; treat device rows (dev_used/dev_free/dev_total) as the authoritative VRAM signal instead. Empty proc rows here != attach failure: these uprobes only fire when an NVML consumer (nvidia-smi/dcgm/accounting agent) calls the probed symbol.")
	return 0
}

// preStartCudaSmutil enables the NVML per-PID SM/compute-utilization probe set.
// It RETARGETS each program to the absolute libnvidia-ml.so.1 path (base-name
// does not resolve for this lib). Whenever any NVML consumer (nvidia-smi, dcgm,
// the GPU accounting agent) calls nvmlDeviceGetProcessUtilization, we decode the
// returned sample[] array and emit one row per PID with its smUtil/memUtil %.
// This is the DIRECT per-PID compute-occupancy signal: a PID that HOLDS VRAM
// (cuda_memsnapshot) but reports smUtil==0% is reserved-but-unused / reclaimable.
// Datasource: smutil_events. Closes the F2 "is it actually using the GPU?" gap
// (follow-up refinement).
func preStartCudaSmutil() int32 {
	const nvml = "/lib/x86_64-linux-gnu/libnvidia-ml.so.1"
	retarget := map[string]string{
		"mep_smutil_enter": nvml + ":nvmlDeviceGetProcessUtilization",
		"mep_smutil_ret":   nvml + ":nvmlDeviceGetProcessUtilization",
	}
	enableExact(retarget)
	pid, ok := readPidParam("cuda_smutil")
	if !ok {
		return 1
	}
	enrichedFilterPid = pid
	enrichedActive = true
	api.Infof("mcp_ebpf_proxy[cuda_smutil]: per-PID SM/compute utilization via NVML uprobes (%d progs) at %s, pid filter=%d", len(smutilPrograms), nvml, pid)
	recordCoverage("cuda_smutil", smutilPrograms, len(smutilPrograms), pid,
		"per-PID SM/compute utilization via NVML uprobes; these only fire when an NVML consumer calls nvmlDeviceGetProcessUtilization. No rows can mean either (a) no NVML consumer ran during the window, or (b) no PID used the SMs. Cross-check with cuda_memsnapshot recent_sm_util to reconcile: a PID holding used_gpu_mem with smUtil==0 is reserved-but-idle. Empty != attach failure.")
	return 0
}

// preStartFixed enables a fixed enriched-family program set (all keep their
// SEC-default attach target, so each is enabled with "") and disables every
// other program with the sentinel. This is the shared PreStart for all of the
// enriched "swiss-army" capabilities (cuda_profile, lock_trace, heap_profile,
// net_trace, fs_trace, mm_trace, irq_trace, block_io, runq_lat): none of them
// takes an agent-supplied attach target, so there is no per-capability symbol
// validation — the targets are compiled-in SEC() defaults. An optional `pid`
// process filter (gadget.yaml) is applied by IG's standard filter, not here.
func preStartFixed(name string, programs []string) int32 {
	keep := map[string]string{}
	for _, pr := range programs {
		keep[pr] = "" // keep each program's SEC-default attach target
	}
	enableExact(keep)
	// Honor the optional `pid` process filter for the process-context families.
	// system-wide families (irq_trace/block_io/runq_lat) fire in softirq/sched
	// context where current!=subject, so the in-kernel guard is a no-op for them
	// even when a pid is set; publishing the map is still harmless/uniform.
	pid, ok := readPidParam(name)
	if !ok {
		return 1
	}
	enrichedFilterPid = pid
	enrichedActive = true
	// fs_trace exposes an additional op-class filter (filter_fs_op) so the agent
	// can isolate failing opens (fs_op=fault|filp_open) from the high-volume
	// vfs_read/vfs_write stream that would otherwise truncate them out of the
	// MCP result. The other families have a single low-rate op set; default 0.
	enrichedFsOp = 0
	if name == "fs_trace" {
		fsop, ok := fsOpFilterValue()
		if !ok {
			return 1
		}
		enrichedFsOp = fsop
		if fsop != 0 {
			api.Infof("mcp_ebpf_proxy[fs_trace]: fs_op filter=%d (1=read 2=write 3=open 4=filp_open 5=fault)", fsop)
		}
	}
	// cuda_profile exposes a parallel op-class filter (filter_cuda_op) so the
	// agent can isolate the PCIe copy rows (cuda_op=copy|h2d|d2h) from the
	// high-rate cuLaunchKernel stream that would otherwise truncate them out of
	// the MCP window. 0 for every other family == CUDA_OP_FILTER_ALL (no-op).
	enrichedCudaOp = 0
	if name == "cuda_profile" {
		cop, ok := cudaOpFilterValue()
		if !ok {
			return 1
		}
		enrichedCudaOp = cop
		if cop != 0 {
			api.Infof("mcp_ebpf_proxy[cuda_profile]: cuda_op filter=%d (1=launch 2=sync 3=copy 4=h2d 5=d2h)", cop)
		}
	}
	if pid != 0 {
		api.Infof("mcp_ebpf_proxy[%s]: enabling %d program(s), pid filter=%d", name, len(programs), pid)
	} else {
		api.Infof("mcp_ebpf_proxy[%s]: enabling %d enriched-family program(s) (all pids)", name, len(programs))
	}
	recordCoverage(name, programs, len(programs), pid,
		"enriched family attached at its SEC-default targets. An empty result means the workload produced no matching events in the window (attached-but-idle), NOT an attach failure — widen duration or pid filter rather than re-selecting the capability.")
	return 0
}

// --------------------------------------------------------- trace_syscall -----

func preStartTraceSyscall() int32 {
	syscall, err := api.GetParamValue("syscall", 64)
	if err != nil {
		api.Errorf("mcp_ebpf_proxy[trace_syscall]: reading syscall param: %s", err)
		return 1
	}

	var nr uint64 = anySyscall
	if syscall != "" {
		id, err := api.GetSyscallID(syscall)
		if err != nil || id < 0 {
			api.Errorf("mcp_ebpf_proxy[trace_syscall]: unknown syscall %q (use a name such as openat, execve, kill); NOTE: for socket/connection detail prefer capability=net_trace (decoded daddr/dport/retransmit) over raw trace_syscall", syscall)
			return 1
		}
		nr = uint64(id)
	}

	pidStr, err := api.GetParamValue("pid", 32)
	if err != nil {
		api.Errorf("mcp_ebpf_proxy[trace_syscall]: reading pid param: %s", err)
		return 1
	}
	var pid uint64
	if pidStr != "" {
		p, err := strconv.ParseUint(pidStr, 10, 32)
		if err != nil {
			api.Errorf("mcp_ebpf_proxy[trace_syscall]: invalid pid %q (must be a non-negative integer)", pidStr)
			return 1
		}
		pid = p
	}

	// Remember the validated filter values; they are written to the BPF maps in
	// gadgetStart (see the var block above for why the writes cannot happen
	// here). Enabling/disabling programs, by contrast, MUST happen now in
	// PreStart because it rewrites the collection spec before load.
	tsFilterNr = nr
	tsFilterPid = pid
	tsActive = true

	// Enable only the two raw-syscall tracepoints (keep their SEC-default attach
	// target — do NOT rewrite attach_to for tracepoints).
	enableExact(map[string]string{progSysEnter: "", progSysExit: ""})

	if syscall == "" {
		api.Infof("mcp_ebpf_proxy[trace_syscall]: tracing ALL syscalls pid=%d", pid)
	} else {
		api.Infof("mcp_ebpf_proxy[trace_syscall]: tracing syscall=%s(nr=%d) pid=%d", syscall, nr, pid)
	}
	return 0
}

func putFilter(mapName string, value uint64) int32 {
	m, err := api.GetMap(mapName)
	if err != nil {
		api.Errorf("mcp_ebpf_proxy[trace_syscall]: getting map %s: %s", mapName, err)
		return 1
	}
	var key uint32 = 0
	if err := m.Put(key, value); err != nil {
		api.Errorf("mcp_ebpf_proxy[trace_syscall]: writing map %s: %s", mapName, err)
		return 1
	}
	return 0
}

// -------------------------------------------------------- list_attachable ----

func preStartListAttachable() int32 {
	// The `filter` (name prefix) and `type` (kallsyms type char) selectors are
	// eBPF rodata params (GADGET_PARAM in program.bpf.c), so the ebpf operator
	// populates them directly from the MCP call at load time -- they are NOT in
	// the WASM param namespace and must not be read here. This control-plane
	// step only has to enable the ksym iterator and disable everything else
	// (keep mep_ksym's SEC-default iter/ksym attach target).
	enableExact(map[string]string{progKsym: ""})
	api.Infof("mcp_ebpf_proxy[list_attachable]: enumerating kallsyms")
	return 0
}

// ------------------------------------------------------------------ start ----

//go:wasmexport gadgetStart
func gadgetStart() int32 {
	// Emit the one-time attach-confirmation / coverage record. PreStart
	// has already recorded what was attached; emitting here (Start stage) means
	// the datasource buffers are live.
	emitCoverageRecord()
	// Maps are only exposed to WASM during the ebpf operator's Start() stage,
	// which runs after PreStart(). So the (pid, syscall) filter maps are written
	// here, mirroring the in-tree traceloop gadget.
	if enrichedActive {
		// Enriched process-context families consult filter_pid + the enabled
		// ready-gate (mep_proc_wanted). Publish filter_pid FIRST, then flip
		// enabled LAST so no event is emitted while the pid filter is still the
		// zero-initialised "any pid" -- this closes the startup leak race for the
		// high-rate kernel families (fs_trace/mm_trace/net_trace).
		if rc := putFilter("filter_pid", enrichedFilterPid); rc != 0 {
			return rc
		}
		// fs_trace op filter (0 for the other families == FS_FILTER_ALL, a no-op).
		if rc := putFilter("filter_fs_op", enrichedFsOp); rc != 0 {
			return rc
		}
		// cuda_profile op filter (0 for the other families == CUDA_OP_FILTER_ALL).
		if rc := putFilter("filter_cuda_op", enrichedCudaOp); rc != 0 {
			return rc
		}
		if rc := putFilter("enabled", 1); rc != 0 {
			return rc
		}
		return 0
	}
	if !tsActive {
		return 0 // attach / list_attachable have no maps to populate
	}
	if rc := putFilter("filter_syscall", tsFilterNr); rc != 0 {
		return rc
	}
	if rc := putFilter("filter_pid", tsFilterPid); rc != 0 {
		return rc
	}
	// Publish the ready-gate LAST: only now are both filters in place, so the
	// tracepoints may begin emitting. This closes the partial-filter race where
	// events from non-target pids could leak between the two writes above.
	if rc := putFilter("enabled", 1); rc != 0 {
		return rc
	}
	return 0
}

// ------------------------------------------------------------------- init ----

//go:wasmexport gadgetInit
func gadgetInit() int32 {
	// Only the `attach` datasource has a per-event `func` column to stamp. The
	// other datasources are self-describing (syscall name / symbol name come
	// from the event itself), so init is a no-op for them.
	ds, err := api.GetDataSource("mep")
	if err != nil {
		// Not fatal: trace_syscall / list_attachable runs do not register "mep".
		// Still register the coverage datasource so those capabilities also emit
		// an attach-confirmation record.
		registerCoverageDataSource()
		return 0
	}
	funcF, err := ds.GetField("func")
	if err != nil {
		return 0
	}
	ds.Subscribe(func(source api.DataSource, data api.Data) {
		if validatedFunc != "" {
			funcF.SetString(data, validatedFunc)
		}
	}, 0)
	registerCoverageDataSource()
	return 0
}

// registerCoverageDataSource creates the one-row mep_coverage datasource used by
// Best-effort: any failure just leaves coverageReady=false (no emit).
func registerCoverageDataSource() {
	cds, err := api.NewDataSource("mep_coverage", api.DataSourceTypeSingle)
	if err != nil {
		return
	}
	if covFieldCap, err = cds.AddField("capability", api.Kind_String); err != nil {
		return
	}
	if covFieldTargets, err = cds.AddField("attached_targets", api.Kind_String); err != nil {
		return
	}
	if covFieldCount, err = cds.AddField("attached_count", api.Kind_Uint32); err != nil {
		return
	}
	if covFieldPid, err = cds.AddField("pid_filter", api.Kind_Uint64); err != nil {
		return
	}
	if covFieldNote, err = cds.AddField("note", api.Kind_String); err != nil {
		return
	}
	coverageDS = cds
	coverageReady = true
}

func main() {}
