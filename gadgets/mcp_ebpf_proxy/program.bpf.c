// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 The Inspektor Gadget authors

// mcp_ebpf_proxy: a single, multi-capability, READ-ONLY kernel-observation
// gadget that exposes generic eBPF/kernel observation to MCP clients through
// ig-mcp-server as ONE MCP tool (gadget_mcp_ebpf_proxy). the MCP client selects a
// `capability` at call time; the WASM control plane (go/program.go) enables
// only that capability's programs and disables the rest with the
// gadget_program_disabled sentinel (checked before the program-type switch in
// pkg/operators/ebpf/attach.go, so it disables kprobe, tracepoint and iter
// programs uniformly).
//
// capability = attach -> mep_kprobe / mep_kretprobe (datasource: events)
// capability = attach_uprobe -> mep_uprobe / mep_uretprobe (datasource: events)
// capability = trace_syscall -> mep_sys_enter / mep_sys_exit (datasource: syscalls)
// capability = cuda_memtrace -> mep_cu_* / mep_cudart_* (datasource: cuda_events)
// capability = list_attachable -> mep_ksym (iter/ksym) (datasource: symbols)
//
// READ-ONLY: only observes registers, raw-tracepoint context and the kallsyms
// iterator. NEVER calls bpf_override_return(), bpf_send_signal() or any writer.

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include <gadget/core_fixes.bpf.h>

#include <gadget/buffer.h>
#include <gadget/common.h>
#include <gadget/macros.h>
#include <gadget/types.h>

// ===========================================================================
// [per_conn_identity] shared socket-identity primitives (per_conn_identity).
// Hoisted so EVERY family stamps the 4-tuple + TCP state where a socket is in
// scope: attach (generic kprobe arg0-as-sock), trace_syscall (fd->sock),
// fs_trace (file->sock on read/write/close), net_trace (sk directly).
// ===========================================================================
#ifndef AF_INET
#define AF_INET  2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif

struct mep_sockid { __u32 saddr, daddr; __u16 sport, dport; __u8 sk_state, sk_family; };

// Decode 4-tuple + TCP state from a struct sock*. SAFE on a garbage pointer:
// the skc_family gate (AF_INET/AF_INET6) rejects non-sockets, leaving
// sk_family=0 ("arg was not an inet socket").
static __always_inline void mep_decode_sk(struct sock *sk, struct mep_sockid *id)
{
	id->saddr = id->daddr = 0; id->sport = id->dport = 0;
	id->sk_state = 0; id->sk_family = 0;
	if (!sk)
		return;
	__u16 fam = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (fam != AF_INET && fam != AF_INET6)
		return;
	id->sk_family = (__u8)fam;
	id->sk_state  = (__u8)BPF_CORE_READ(sk, __sk_common.skc_state);
	id->daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
	id->saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
	id->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
	id->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
}

// Resolve struct file* -> struct sock* (NULL if not a socket). Validates the
// socket->file back-pointer to reject a file whose private_data is not a socket.
static __always_inline struct sock *mep_sock_from_file(struct file *file)
{
	if (!file)
		return 0;
	struct socket *sock = BPF_CORE_READ(file, private_data);
	if (!sock)
		return 0;
	if (BPF_CORE_READ(sock, file) != file)
		return 0;
	return BPF_CORE_READ(sock, sk);
}

// ===========================================================================
// capability: attach -- runtime-retargetable kprobe/kretprobe
// (kept byte-identical to the proven first-cut programs)
// ===========================================================================

enum mep_phase {
	enter,	// kprobe / sys_enter
	ret,	// kretprobe / sys_exit
};

struct event {
	gadget_timestamp timestamp_raw;
	struct gadget_process proc;

	enum mep_phase phase_raw;
	// func is filled by the WASM enricher with the validated symbol name; kept
	// as a fixed buffer so the column exists in the datasource schema.
	char func[40];
	__u64 arg0;
	__u64 arg1;
	__u64 arg2;
	__u64 arg3;
	__u64 arg4;
	__s64 retval;
	// [per_conn_identity attach] best-effort socket identity when arg0 is a
	// struct sock* (the dominant net-family kprobe target: tcp_*, udp_*,
	// inet_*). sk_family=0 => arg0 was not an inet socket (ignore the 4-tuple).
	__u32 saddr, daddr;
	__u16 sport, dport;
	__u8  sk_state, sk_family;
	// [uprobe_pairing] in-flight recursion depth for this tid at THIS uprobe
	// hit: 1 on the outermost entry, 2 on a self-recursive re-entry,... and
	// the matching value on the paired return. Automates the
	// entry-vs-return hand-diff (unbalanced depth == a return that never fired).
	__u32 call_depth;
	// [stack_watermark] bytes of user stack consumed since the OUTERMOST uprobe
	// entry of this tid's current call chain (0 at the outermost frame; grows as
	// recursion/nesting deepens). = entry_sp - PT_REGS_SP(ctx). Lets an MCP client
	// watch a recursive path march toward the 8MiB thread-stack rlimit (runaway recursion,
	// stack-exhaustion shape) without hand-diffing frame pointers. 0 on non-uprobe rows.
	__u64 stack_used;
	// [stack_watermark] 1 on the ONE-SHOT row where stack_used first crossed the
	// stack_watermark_bytes threshold for this call chain (else 0). Fires at most
	// once per tid call chain so a deep recursion does not spam an alarm per frame.
	__u8  stack_alarm;
	// [uprobe_argdecode] symbolized/string decode of a user-space argument at
	// a uprobe: the actual $ref (path, host, method, Rust &str) instead of a
	// raw pointer. Filled only when the uprobe_str_arg param selects an arg.
	char arg_str[128];
};

GADGET_TRACER_MAP(events, 1024 * 256);
GADGET_TRACER(mep, events, event);

static __always_inline struct event *mep_new(enum mep_phase phase)
{
	struct event *e = gadget_reserve_buf(&events, sizeof(*e));
	if (!e)
		return 0;
	e->timestamp_raw = bpf_ktime_get_boot_ns();
	gadget_process_populate(&e->proc);
	e->phase_raw = phase;
	e->func[0] = '\0';
	e->arg0 = e->arg1 = e->arg2 = e->arg3 = e->arg4 = 0;
	e->retval = 0;
	e->saddr = e->daddr = 0; e->sport = e->dport = 0;
	e->sk_state = e->sk_family = 0;
	e->call_depth = 0;
	e->stack_used = 0; e->stack_alarm = 0;
	return e;
}

SEC("kprobe/mep_dummy")
int BPF_KPROBE(mep_kprobe)
{
	struct event *e = mep_new(enter);
	if (!e)
		return 0;
	e->arg0 = (__u64)PT_REGS_PARM1(ctx);
	e->arg1 = (__u64)PT_REGS_PARM2(ctx);
	e->arg2 = (__u64)PT_REGS_PARM3(ctx);
	e->arg3 = (__u64)PT_REGS_PARM4(ctx);
	e->arg4 = (__u64)PT_REGS_PARM5(ctx);
	// [per_conn_identity attach] stamp the 4-tuple+state if arg0 is a sock.
	{ struct mep_sockid _id; mep_decode_sk((struct sock *)e->arg0, &_id);
	  e->saddr = _id.saddr; e->daddr = _id.daddr; e->sport = _id.sport;
	  e->dport = _id.dport; e->sk_state = _id.sk_state; e->sk_family = _id.sk_family; }
	gadget_submit_buf(ctx, &events, e, sizeof(*e));
	return 0;
}

SEC("kretprobe/mep_dummy")
int BPF_KRETPROBE(mep_kretprobe, long retval)
{
	struct event *e = mep_new(ret);
	if (!e)
		return 0;
	e->retval = (__s64)retval;
	gadget_submit_buf(ctx, &events, e, sizeof(*e));
	return 0;
}

// ===========================================================================
// capability: trace_syscall -- raw_syscalls sys_enter/sys_exit, filtered by
// (pid, syscall-nr). Filters are populated from WASM via BPF maps because
// gadgetPreStart() runs AFTER the eBPF object is loaded, so rodata globals
// cannot carry the MCP client's runtime values for this capability.
// ===========================================================================

// [errno_decode] Failure-mode buckets for a syscall retval. Lets an MCP client see
// WHY a connect failed (refused vs unreachable vs timed-out vs still-in-flight)
// without memorising errno numbers. Auto-decoded by IG from BTF
// (err_class_raw -> "errc_refused").
enum mep_errclass {
	errc_ok,		// retval >= 0
	errc_inprogress,	// EINPROGRESS/EAGAIN -- async connect in flight (normal)
	errc_refused,		// ECONNREFUSED -- peer up, port closed (RST)
	errc_unreachable,	// EHOSTUNREACH/ENETUNREACH -- no route to peer
	errc_timedout,		// ETIMEDOUT -- peer silent (dropped SYN / dead host)
	errc_reset,		// ECONNRESET/EPIPE -- peer tore down an established conn
	errc_other,		// any other negative errno
};

struct syscall_event {
	gadget_timestamp timestamp_raw;
	struct gadget_process proc;

	gadget_syscall syscall_nr_raw;	// type triggers IG formatter -> decoded `syscall` field
	enum mep_phase phase_raw;
	__u64 arg0;
	__u64 arg1;
	__u64 arg2;
	__u64 arg3;
	__u64 arg4;
	__u64 arg5;
	__s64 retval;
	gadget_duration duration_ns;	// enter->ret wall-clock (ret rows); 0 on enter rows
	// [per_conn_identity] socket 4-tuple + TCP state, resolved from the fd arg
	// (arg0) for socket syscalls (connect/sendto/recvfrom/read/write/sendmsg/
	// recvmsg/close/accept). Zero for non-socket fds / non-fd syscalls. Cached
	// at enter and re-stamped on the exit row so the retval/errno row ALSO
	// carries the peer identity (e.g. connect()==-ECONNREFUSED to daddr:dport).
	__u32 saddr;		// local IPv4 (network order); 0 if unresolved
	__u32 daddr;		// remote IPv4 (network order); 0 if unresolved
	__u16 sport;		// local port (host order)
	__u16 dport;		// remote port (host order)
	__u8  sk_state;		// TCP state (1=ESTABLISHED,8=CLOSE_WAIT,...); 0 if unresolved
	__u8  sk_family;	// 2=AF_INET,10=AF_INET6; 0 if fd is not an inet socket
	// [errno_decode] classified failure mode of retval (see enum mep_errclass).
	gadget_errno err_raw;		// positive errno (0 on success); IG symbolises name
	enum mep_errclass err_class_raw;
};

GADGET_TRACER_MAP(syscalls, 1024 * 256);
GADGET_TRACER(mep_sys, syscalls, syscall_event);

// [errno_decode] Map a syscall retval to (positive errno, failure class).
static __always_inline enum mep_errclass mep_classify_errno(__s64 ret, __u32 *err_out)
{
	if (ret >= 0) { *err_out = 0; return errc_ok; }
	__u32 e = (__u32)(-ret);
	*err_out = e;
	switch (e) {
	case 115: /* EINPROGRESS */
	case 11:  /* EAGAIN */
		return errc_inprogress;
	case 111: /* ECONNREFUSED */
		return errc_refused;
	case 113: /* EHOSTUNREACH */
	case 101: /* ENETUNREACH */
	case 112: /* EHOSTDOWN */
		return errc_unreachable;
	case 110: /* ETIMEDOUT */
		return errc_timedout;
	case 104: /* ECONNRESET */
	case 32:  /* EPIPE */
		return errc_reset;
	default:
		return errc_other;
	}
}

// [errno_decode / causal death] Per-process (tgid) record of the LAST FAILED
// socket syscall: its errno + intended 4-tuple + when. On process exit the
// sched_process_exit probe pairs this with the exit code so an MCP client can answer
// "did this process die BECAUSE of that refused connect?" (a process that died after a refused dependency connect). Keyed by
// tgid; overwritten by each new failure; consumed+deleted at exit.
struct mep_sockfail {
	__u64 ts;		// boot-ns of the failure
	__u32 err;		// positive errno
	__u32 nr;		// syscall nr that failed (42=connect,...)
	__u32 saddr, daddr;
	__u16 sport, dport;
	__u8  err_class;	// enum mep_errclass
	__u8  sk_family;
};
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);		// tgid
	__type(value, struct mep_sockfail);
} last_sockfail SEC(".maps");

#define MEP_ANY_SYSCALL 0xffffffffULL

// 1-entry arrays populated by WASM gadgetPreStart() via GetMap().Put().
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} filter_syscall SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} filter_pid SEC(".maps");

// Ready-gate. Defaults to 0 (= drop every event) at load. The WASM control
// plane flips it to 1 in gadgetStart AFTER both filter maps are populated, so
// no event can be emitted while the (pid, syscall) filters are only partially
// written. Without this gate, the two non-atomic filter-map writes leave a
// sub-millisecond window where filter_syscall matches but filter_pid is still
// the zero-initialised "any pid", leaking events from non-target processes.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} enabled SEC(".maps");

// per-task scratch: remember the syscall nr + enter timestamp seen at enter so
// sys_exit can match it arch-independently (avoids reading orig_ax at exit) AND
// compute the per-call duration.
struct mep_sysactive {
	__u64 nr; __u64 ts;
	// [per_conn_identity] cache the enter-time socket identity so the exit row
	// (which carries retval/duration) is stamped with the SAME 4-tuple+state.
	__u32 saddr, daddr; __u16 sport, dport; __u8 sk_state, sk_family;
};
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);	// pid_tgid
	__type(value, struct mep_sysactive);	// nr + enter ts
} active_syscall SEC(".maps");

static __always_inline bool mep_sys_wanted(__u64 nr)
{
	__u32 k = 0;
	__u64 *on = bpf_map_lookup_elem(&enabled, &k);
	if (!on || *on == 0)
		return false;	// filters not fully published yet -> drop
	__u64 *want_nr = bpf_map_lookup_elem(&filter_syscall, &k);
	if (want_nr && *want_nr != MEP_ANY_SYSCALL && *want_nr != nr)
		return false;

	__u64 *want_pid = bpf_map_lookup_elem(&filter_pid, &k);
	if (want_pid && *want_pid != 0) {
		__u64 pid = bpf_get_current_pid_tgid() >> 32;
		if (pid != *want_pid)
			return false;
	}
	return true;
}

// Shared process filter for the ENRICHED swiss-army families. The `pid` param
// (gadget.yaml) is published into the filter_pid map by the WASM control plane
// (gadgetStart -> putFilter). When set to a non-zero pid, only events whose
// CURRENT task tgid matches are emitted; pid==0 (the load-time default) means
// "all processes" so the families are unfiltered unless the MCP client asks for a
// pid. This runs in the TARGET process context for the userspace-uprobe
// families (cuda/cuprof/lock/heap) and the syscall context for the kernel
// process-context families (net connect/sendmsg, fs read/write/open, mm fault/
// reclaim), so bpf_get_current_pid_tgid() identifies the subject under test.
// System-wide families (irq_trace/block_io/runq_lat) fire in softirq/scheduler
// context where current!=subject and are intentionally NOT gated by this.
static __always_inline bool mep_proc_wanted(void)
{
	__u32 k = 0;
	// Ready-gate: enabled defaults to 0 at load and is flipped to 1 by the WASM
	// control plane (gadgetStart) only AFTER filter_pid has been published. This
	// closes the startup race where filter_pid is still the zero-initialised
	// "any pid", which would otherwise leak non-target events from the high-rate
	// kernel families (vfs_*, etc.) in the window before the pid filter lands.
	__u64 *on = bpf_map_lookup_elem(&enabled, &k);
	if (!on || *on == 0)
		return false;
	__u64 *want_pid = bpf_map_lookup_elem(&filter_pid, &k);
	if (want_pid && *want_pid != 0) {
		__u64 pid = bpf_get_current_pid_tgid() >> 32;
		if (pid != *want_pid)
			return false;
	}
	return true;
}

// [per_conn_identity] Resolve a socket fd -> inet 4-tuple + TCP state via a
// CO-RE fd-table walk (task->files->fdt->fd[n]->private_data as struct socket).
// SAFE against non-socket fds: we validate the socket->file back-pointer equals
// the file we walked from, then require skc_family in {AF_INET,AF_INET6}. Any
// mismatch leaves the identity zeroed. Best-effort + read-only; a failed walk
// (bad fd, closed race, non-inet) simply yields sk_family==0.

static __always_inline void mep_resolve_sock_fd(int fd, struct mep_sockid *id)
{
	id->saddr = id->daddr = 0; id->sport = id->dport = 0;
	id->sk_state = 0; id->sk_family = 0;
	if (fd < 0 || fd >= 4096)
		return;
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	if (!task)
		return;
	struct files_struct *files = BPF_CORE_READ(task, files);
	if (!files)
		return;
	struct fdtable *fdt = BPF_CORE_READ(files, fdt);
	if (!fdt)
		return;
	unsigned int max_fds = BPF_CORE_READ(fdt, max_fds);
	if ((unsigned int)fd >= max_fds)
		return;
	struct file **fd_array = BPF_CORE_READ(fdt, fd);
	if (!fd_array)
		return;
	struct file *file = NULL;
	bpf_probe_read_kernel(&file, sizeof(file), fd_array + fd);
	// shared decode: file -> sock -> 4-tuple + state (per_conn_identity primitives).
	mep_decode_sk(mep_sock_from_file(file), id);
}

// [per_conn_identity/errno_decode] Read the INTENDED destination from a
// userspace sockaddr pointer (connect(2) arg1, sendto(2) arg4). This fills in
// daddr:dport even when the fd-resolved sock has no peer yet — i.e. on a
// connect that is about to fail (ECONNREFUSED/EHOSTUNREACH) the row still names
// the endpoint the process tried to reach. AF_INET only; best-effort user read.
static __always_inline void mep_read_uaddr_dest(__u64 uaddr, __u32 *daddr, __u16 *dport)
{
	if (!uaddr)
		return;
	struct { __u16 fam; __u16 port; __u32 addr; } sa = {};
	if (bpf_probe_read_user(&sa, sizeof(sa), (void *)uaddr) != 0)
		return;
	if (sa.fam != AF_INET)
		return;
	*dport = bpf_ntohs(sa.port);
	*daddr = sa.addr;	// already network order
}

// x86_64 socket-relevant syscalls whose arg0 is an fd worth resolving. Kept
// tight so the fd-table walk only runs on connection-carrying calls, not on
// the whole syscall firehose.
static __always_inline bool mep_is_sockcall(__u64 nr)
{
	switch (nr) {
	case 0:   // read
	case 1:   // write
	case 3:   // close
	case 42:  // connect
	case 43:  // accept
	case 44:  // sendto
	case 45:  // recvfrom
	case 46:  // sendmsg
	case 47:  // recvmsg
	case 48:  // shutdown
	case 288: // accept4
		return true;
	default:
		return false;
	}
}

SEC("raw_tracepoint/sys_enter")
int mep_sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
	// ctx->args[0] = struct pt_regs *, ctx->args[1] = long syscall id
	__u64 nr = (__u64)ctx->args[1];
	if (!mep_sys_wanted(nr))
		return 0;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 now = bpf_ktime_get_boot_ns();
	struct mep_sysactive act = { .nr = nr, .ts = now };
	bpf_map_update_elem(&active_syscall, &pid_tgid, &act, BPF_ANY);

	struct syscall_event *e = gadget_reserve_buf(&syscalls, sizeof(*e));
	if (!e)
		return 0;
	e->timestamp_raw = now;
	gadget_process_populate(&e->proc);
	e->syscall_nr_raw = nr;
	e->phase_raw = enter;
	e->duration_ns = 0;	// enter row has no duration

	struct pt_regs *regs = (struct pt_regs *)ctx->args[0];
	e->arg0 = (__u64)PT_REGS_PARM1_CORE_SYSCALL(regs);
	e->arg1 = (__u64)PT_REGS_PARM2_CORE_SYSCALL(regs);
	e->arg2 = (__u64)PT_REGS_PARM3_CORE_SYSCALL(regs);
	e->arg3 = (__u64)PT_REGS_PARM4_CORE_SYSCALL(regs);
	e->arg4 = (__u64)PT_REGS_PARM5_CORE_SYSCALL(regs);
	e->arg5 = (__u64)PT_REGS_PARM6_CORE_SYSCALL(regs);
	e->retval = 0;
	// [per_conn_identity] resolve fd(arg0) -> 4-tuple+state for socket syscalls,
	// stamp this enter row AND cache it for the matching exit row.
	e->saddr = e->daddr = 0; e->sport = e->dport = 0; e->sk_state = e->sk_family = 0;
	if (mep_is_sockcall(nr)) {
		struct mep_sockid id;
		mep_resolve_sock_fd((int)e->arg0, &id);
		// connect(2): dest sockaddr is arg1; sendto(2): arg4. Fill the intended
		// destination from userspace when the sock has no peer yet (pre/failed
		// connect) so the row names WHO the process tried to reach.
		if (id.daddr == 0) {
			if (nr == 42)       // connect
				mep_read_uaddr_dest(e->arg1, &id.daddr, &id.dport);
			else if (nr == 44)  // sendto
				mep_read_uaddr_dest(e->arg4, &id.daddr, &id.dport);
			if (id.daddr && id.sk_family == 0)
				id.sk_family = AF_INET;	// mark as inet even if fd-walk missed
		}
		e->saddr = id.saddr; e->daddr = id.daddr;
		e->sport = id.sport; e->dport = id.dport;
		e->sk_state = id.sk_state; e->sk_family = id.sk_family;
		if (id.sk_family) {
			struct mep_sysactive *ap = bpf_map_lookup_elem(&active_syscall, &pid_tgid);
			if (ap) {
				ap->saddr = id.saddr; ap->daddr = id.daddr;
				ap->sport = id.sport; ap->dport = id.dport;
				ap->sk_state = id.sk_state; ap->sk_family = id.sk_family;
			}
		}
	}
	gadget_submit_buf(ctx, &syscalls, e, sizeof(*e));
	return 0;
}

SEC("raw_tracepoint/sys_exit")
int mep_sys_exit(struct bpf_raw_tracepoint_args *ctx)
{
	// ctx->args[1] = long ret. Recover nr from the per-task scratch recorded
	// at enter; absence means this syscall was filtered out at enter.
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct mep_sysactive *ap = bpf_map_lookup_elem(&active_syscall, &pid_tgid);
	if (!ap)
		return 0;
	__u64 nr = ap->nr;
	__u64 enter_ts = ap->ts;
	// [per_conn_identity] copy cached socket identity out BEFORE deleting.
	struct mep_sockid xid = { .saddr = ap->saddr, .daddr = ap->daddr,
		.sport = ap->sport, .dport = ap->dport,
		.sk_state = ap->sk_state, .sk_family = ap->sk_family };
	bpf_map_delete_elem(&active_syscall, &pid_tgid);

	__u64 now = bpf_ktime_get_boot_ns();
	struct syscall_event *e = gadget_reserve_buf(&syscalls, sizeof(*e));
	if (!e)
		return 0;
	e->timestamp_raw = now;
	gadget_process_populate(&e->proc);
	e->syscall_nr_raw = nr;
	e->phase_raw = ret;
	e->arg0 = e->arg1 = e->arg2 = e->arg3 = e->arg4 = e->arg5 = 0;
	e->retval = (__s64)ctx->args[1];
	// [errno_decode] classify the failure mode (refused/unreachable/timed-out).
	{
		__u32 _errno = 0;
		e->err_class_raw = mep_classify_errno(e->retval, &_errno);
		e->err_raw = _errno;
	}
	// per-call wall-clock — no manual enter/ret correlation needed.
	e->duration_ns = (enter_ts && now > enter_ts) ? (now - enter_ts) : 0;
	// [per_conn_identity] stamp the exit row with the enter-time identity so the
	// retval/errno (e.g. connect==-ECONNREFUSED) is attributed to the peer.
	e->saddr = xid.saddr; e->daddr = xid.daddr;
	e->sport = xid.sport; e->dport = xid.dport;
	e->sk_state = xid.sk_state; e->sk_family = xid.sk_family;
	// [errno_decode/causal death] remember a FAILED socket syscall for this
	// process so a later exit can be attributed to it. Skip the benign
	// EINPROGRESS async-connect path (not a real failure).
	if (e->retval < 0 && e->err_class_raw != errc_inprogress && mep_is_sockcall(nr)) {
		__u32 _tgid = pid_tgid >> 32;
		struct mep_sockfail _rec = {
			.ts = now, .err = e->err_raw, .nr = (__u32)nr,
			.saddr = e->saddr, .daddr = e->daddr,
			.sport = e->sport, .dport = e->dport,
			.err_class = (__u8)e->err_class_raw, .sk_family = e->sk_family,
		};
		bpf_map_update_elem(&last_sockfail, &_tgid, &_rec, BPF_ANY);
	}
	gadget_submit_buf(ctx, &syscalls, e, sizeof(*e));
	return 0;
}


// ===========================================================================
// capability: attach_uprobe -- runtime-retargetable uprobe/uretprobe on an
// arbitrary userspace symbol. Mirrors `attach` (kprobe) but for user space.
// The WASM control plane rewrites programs.mep_uprobe.attach_to (and
//.mep_uretprobe) to "<lib-or-abs-path>:<symbol>", e.g.
// /usr/lib/x86_64-linux-gnu/libssl.so.3:SSL_read (absolute path), or
// libc:malloc (library name; resolved
// via the target's /etc/ld.so.cache by IG's uprobetracer). The SEC default
// below is a harmless self-reference ("ig:__mep_uprobe_dummy") so the object
// loads even when this capability is disabled; the real target always arrives
// through the attach_to config override (pkg/operators/ebpf/attach.go:50).
// READ-ONLY: only reads the probed function's argument registers + return.
// ===========================================================================

// [uprobe_pairing] per-tid uprobe call bookkeeping. depth is the live in-flight
// count (enter++ / return--), which gives automatic enter<->return pairing and
// a per-tid recursion-depth signal. entry_sp is reserved for stack_watermark
// (stack_watermark) and initialised here so the two items share one map.
struct mep_uctx { __u32 depth; __u64 entry_sp; __u8 alarmed; };
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, __u32);
	__type(value, struct mep_uctx);
} mep_uctx_map SEC(".maps");

// [stack_watermark] one-shot alarm threshold in BYTES of stack consumed since
// the outermost uprobe entry. 0 (default) disables the alarm (stack_used is
// still emitted on every uprobe row). A typical 8MiB thread stack overflows
// around 8*1024*1024; set e.g. 6291456 (6MiB) to fire before the guard page.
const volatile __u32 stack_watermark_bytes = 0;
GADGET_PARAM(stack_watermark_bytes);

// [uprobe_argdecode] which uprobe arg (0-4) is a pointer to a user string to
// decode into arg_str; 0xff (default) disables the decode. uprobe_str_len_arg
// (0-4) optionally names an arg holding an explicit byte length for a
// non-NUL-terminated string (Rust &str fat pointer: ptr,len); 0xff => read a
// C NUL-terminated string. Lets an MCP client read the $ref at a uprobe.
const volatile __u32 uprobe_str_arg = 0xff;
GADGET_PARAM(uprobe_str_arg);
const volatile __u32 uprobe_str_len_arg = 0xff;
GADGET_PARAM(uprobe_str_len_arg);

// [kern_user_correlate] which uprobe arg (0-4) holds a file descriptor to
// resolve into the kernel struct sock (fd -> 4-tuple + state); 0xff (default)
// disables it. Binds a userspace uprobe hit (an app connection object passed
// by fd) to the kernel socket identity — the kernel<->userspace correlation
// ask (uprobe emits fd -> bind struct sock to app conn object).
const volatile __u32 uprobe_fd_arg = 0xff;
GADGET_PARAM(uprobe_fd_arg);

SEC("uprobe/__mep_uprobe_dummy")
int BPF_UPROBE(mep_uprobe)
{
	/* host-uprobe recipe: host mode attaches to all host processes that
	 * map the target inode. Gate the emitted event stream by filter_pid so
	 * --host --pid=<target-host-pid> yields target-PID rows only, not ambient
	 * host malloc/cuda noise. The WASM control plane publishes filter_pid and
	 * flips enabled last (ready gate) in gadgetStart(). */
	if (!mep_proc_wanted())
		return 0;
	struct event *e = mep_new(enter);
	if (!e)
		return 0;
	e->arg0 = (__u64)PT_REGS_PARM1(ctx);
	e->arg1 = (__u64)PT_REGS_PARM2(ctx);
	e->arg2 = (__u64)PT_REGS_PARM3(ctx);
	e->arg3 = (__u64)PT_REGS_PARM4(ctx);
	e->arg4 = (__u64)PT_REGS_PARM5(ctx);
	// [uprobe_argdecode] optionally decode a user-space string argument at this
	// uprobe. uprobe_str_arg picks which arg (0-4) is the pointer; with
	// uprobe_str_len_arg set we read an explicit length (Rust &str), else a C
	// NUL-terminated string. arg_str stays empty on non-string uprobes.
	if (uprobe_str_arg <= 4) {
		__u64 uargs[8] = { e->arg0, e->arg1, e->arg2, e->arg3, e->arg4, 0, 0, 0 };
		__u64 p = uargs[uprobe_str_arg & 7];
		if (p) {
			if (uprobe_str_len_arg <= 4) {
				__u64 n = uargs[uprobe_str_len_arg & 7];
				if (n >= sizeof(e->arg_str))
					n = sizeof(e->arg_str) - 1;
				bpf_probe_read_user(e->arg_str, n, (void *)p);
				// terminate at the ACTUAL length: a shorter read must not
				// expose stale ringbuf-slot tail bytes from a prior event
				// (the doubling seen in unit-proof v1: 'envoy...15001er-...15001').
				e->arg_str[n] = 0;
			} else {
				bpf_probe_read_user_str(e->arg_str, sizeof(e->arg_str), (void *)p);
			}
		}
	}
	// [kern_user_correlate] optionally resolve a file-descriptor argument at
	// this uprobe into the kernel socket identity (4-tuple + state), binding
	// the userspace conn object to the kernel struct sock. Runs in the target
	// task context, so bpf_get_current_task()'s fd table is the app's own.
	// sk_family stays 0 when the arg is not an inet socket fd (leave it alone
	// so an attach-family sock* decode, if any, is not clobbered).
	if (uprobe_fd_arg <= 4) {
		__u64 fargs[8] = { e->arg0, e->arg1, e->arg2, e->arg3, e->arg4, 0, 0, 0 };
		struct mep_sockid _id;
		mep_resolve_sock_fd((int)fargs[uprobe_fd_arg & 7], &_id);
		if (_id.sk_family) {
			e->saddr = _id.saddr; e->daddr = _id.daddr;
			e->sport = _id.sport; e->dport = _id.dport;
			e->sk_state = _id.sk_state; e->sk_family = _id.sk_family;
		}
	}
	// [uprobe_pairing] bump this tid's in-flight depth and stamp it.
	// [stack_watermark] on the OUTERMOST entry, stamp entry_sp = current user SP
	// as the call chain's stack base; on deeper hits emit stack_used = base - sp
	// and fire a one-shot alarm the first time it crosses stack_watermark_bytes.
	{
		__u32 tid = (__u32)bpf_get_current_pid_tgid();
		__u64 sp = PT_REGS_SP(ctx);
		struct mep_uctx *u = bpf_map_lookup_elem(&mep_uctx_map, &tid);
		// [stack_watermark] Detect the OUTERMOST frame by stack GEOMETRY, not by
		// the uretprobe unwind count. On x86-64 the stack grows DOWN, so a deeper
		// frame always has a strictly lower SP than its caller. If we have no
		// context OR the current SP has risen back to/above the stored chain base
		// (u->entry_sp), the previous chain has fully unwound and this is a fresh
		// outermost call -- even if some uretprobes were MISSED (which would
		// otherwise leave mep_uctx->depth drifting upward across chains, the
		// call_depth=21162 bug). Re-anchor: reset depth=1 and re-stamp entry_sp to
		// this SP so call_depth is bounded per chain and stack_used is measured
		// from the true current base, never a stale one.
		if (!u || sp >= u->entry_sp) {
			struct mep_uctx nu = { .depth = 1, .entry_sp = sp, .alarmed = 0 };
			bpf_map_update_elem(&mep_uctx_map, &tid, &nu, BPF_ANY);
			e->call_depth = 1;
			e->stack_used = 0;
		} else {
			/* sp < u->entry_sp guaranteed by the branch above */
			u->depth += 1;
			e->call_depth = u->depth;
			__u64 used = u->entry_sp - sp;
			e->stack_used = used;
			if (stack_watermark_bytes && !u->alarmed &&
			    used > (__u64)stack_watermark_bytes) {
				u->alarmed = 1;
				e->stack_alarm = 1;
			}
		}
	}
	gadget_submit_buf(ctx, &events, e, sizeof(*e));
	return 0;
}

SEC("uretprobe/__mep_uprobe_dummy")
int BPF_URETPROBE(mep_uretprobe, long retval)
{
	/* Same host-PID gate as mep_uprobe: keep entry/return attribution symmetric. */
	if (!mep_proc_wanted())
		return 0;
	struct event *e = mep_new(ret);
	if (!e)
		return 0;
	e->retval = (__s64)retval;
	// [uprobe_pairing] pair this return to the entry depth, then unwind.
	{
		__u32 tid = (__u32)bpf_get_current_pid_tgid();
		struct mep_uctx *u = bpf_map_lookup_elem(&mep_uctx_map, &tid);
		if (u) {
			e->call_depth = u->depth;	// depth of the frame we are LEAVING
			if (u->depth <= 1)
				bpf_map_delete_elem(&mep_uctx_map, &tid);
			else
				u->depth -= 1;
		}
	}
	gadget_submit_buf(ctx, &events, e, sizeof(*e));
	return 0;
}

// ===========================================================================
// capability: cuda_memtrace -- CUDA GPU memory alloc/free leak tracing via
// uprobes on the CUDA driver (libcuda) and runtime (libcudart) allocators.
// Emits one `cuda_event` per alloc and per free with the exact byte size and
// device pointer, so an MCP client can reconcile alloc/free pairs and flag leaks
// (allocations with no matching free while a process is alive). Tracking is
// per (pid, ptr) because device pointers are per-process. This is the
// client-facing, event-streaming counterpart of the upstream top_cuda_memory
// gadget (which only keeps per-process running totals). Driver + runtime are
// traced as SEPARATE libraries because cudaMalloc internally calls
// cuMemAlloc_v2 on the same thread; sharing a per-tid context map would let
// the nested driver uprobe clobber the runtime context.
// READ-ONLY: pure observation of the allocator ABI; never alters returns.
// ===========================================================================

enum cuda_op {
	cuda_alloc,	// allocation succeeded; size + ptr valid
	cuda_free,	// free called; ptr valid, size resolved from tracking map
	cuda_alloc_fail, // allocator returned non-zero; size valid, ptr = 0
};

struct cuda_event {
	gadget_timestamp timestamp_raw;
	struct gadget_process proc;

	enum cuda_op op_raw;
	__u8 is_runtime;	// 0 = libcuda (driver API), 1 = libcudart (runtime API)
	__u8 pad[6];
	__u64 size;		// bytes (alloc: requested; free: size of the freed block if known)
	__u64 ptr;		// device/host pointer value
	__s64 retval;		// allocator/free return code (0 == CUDA_SUCCESS)
};

GADGET_TRACER_MAP(cuda_events, 1024 * 256);
GADGET_TRACER(mep_cuda, cuda_events, cuda_event);

#define CUDA_MAX_ENTRIES 10240

// (pid, ptr) -> size, one map per library so a runtime free matches a runtime
// alloc even when the nested driver alloc also fired for the same bytes.
struct cuda_alloc_key {
	__u64 pid;
	__u64 ptr;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, CUDA_MAX_ENTRIES);
	__type(key, struct cuda_alloc_key);
	__type(value, __u64);	// size
} cuda_driver_sizes SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, CUDA_MAX_ENTRIES);
	__type(key, struct cuda_alloc_key);
	__type(value, __u64);	// size
} cuda_runtime_sizes SEC(".maps");

// per-tid scratch carrying the alloc request from uprobe -> uretprobe.
// Keyed by TID because concurrent threads can allocate at once; PID keying
// would let one thread's uprobe overwrite another's pending context.
struct cuda_pending {
	__u64 size;	// requested bytes
	__u64 ptr_loc;	// user address where the allocator writes the result pointer
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, CUDA_MAX_ENTRIES);
	__type(key, __u32);	// tid
	__type(value, struct cuda_pending);
} cuda_driver_pending SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, CUDA_MAX_ENTRIES);
	__type(key, __u32);	// tid
	__type(value, struct cuda_pending);
} cuda_runtime_pending SEC(".maps");

// per-tid scratch carrying the freed pointer from free uprobe -> uretprobe,
// so the size is only credited (and the tracking entry deleted) once the free
// actually succeeds.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, CUDA_MAX_ENTRIES);
	__type(key, __u32);	// tid
	__type(value, __u64);	// ptr being freed
} cuda_driver_freeing SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, CUDA_MAX_ENTRIES);
	__type(key, __u32);	// tid
	__type(value, __u64);	// ptr being freed
} cuda_runtime_freeing SEC(".maps");

static __always_inline __u32 cuda_tid(void)
{
	return (__u32)bpf_get_current_pid_tgid();
}

// ---- alloc enter: stash (size, ptr_loc) keyed by tid -----------------------
static __always_inline int cuda_alloc_enter(void *pending_map, __u64 ptr_loc,
					    __u64 size)
{
	/* host-PID attribution: host CUDA uprobes attach broadly, so
	 * reject non-target host processes before staging per-tid pending state. */
	if (!mep_proc_wanted())
		return 0;
	__u32 tid = cuda_tid();
	struct cuda_pending p = {};
	p.size = size;
	p.ptr_loc = ptr_loc;
	bpf_map_update_elem(pending_map, &tid, &p, BPF_ANY);
	return 0;
}

// ---- alloc exit: read the written pointer, record (pid,ptr)->size, emit ----
static __always_inline int cuda_alloc_exit(void *ctx, void *pending_map,
					   void *sizes_map, __u8 is_runtime,
					   long ret)
{
	__u32 tid = cuda_tid();
	struct cuda_pending *p = bpf_map_lookup_elem(pending_map, &tid);
	if (!p)
		return 0;
	__u64 size = p->size;
	__u64 ptr_loc = p->ptr_loc;
	bpf_map_delete_elem(pending_map, &tid);

	__u64 ptr = 0;
	if (ptr_loc)
		bpf_probe_read_user(&ptr, sizeof(ptr), (void *)ptr_loc);

	if (!mep_proc_wanted())
		return 0;
	struct cuda_event *e = gadget_reserve_buf(&cuda_events, sizeof(*e));
	if (!e)
		return 0;
	e->timestamp_raw = bpf_ktime_get_boot_ns();
	gadget_process_populate(&e->proc);
	e->is_runtime = is_runtime;
	e->size = size;
	e->retval = (__s64)ret;

	if (ret != 0 || ptr == 0) {
		// allocation failed: report it, do not track.
		e->op_raw = cuda_alloc_fail;
		e->ptr = 0;
		gadget_submit_buf(ctx, &cuda_events, e, sizeof(*e));
		return 0;
	}

	e->op_raw = cuda_alloc;
	e->ptr = ptr;
	gadget_submit_buf(ctx, &cuda_events, e, sizeof(*e));

	struct cuda_alloc_key k = {};
	k.pid = bpf_get_current_pid_tgid() >> 32;
	k.ptr = ptr;
	bpf_map_update_elem(sizes_map, &k, &size, BPF_ANY);
	return 0;
}

// ---- free enter: stash the freed ptr keyed by tid --------------------------
static __always_inline int cuda_free_enter(void *freeing_map, __u64 ptr)
{
	/* Same target-PID gate as alloc enter: no ambient host frees in target-only
	 * captures. */
	if (!mep_proc_wanted())
		return 0;
	__u32 tid = cuda_tid();
	bpf_map_update_elem(freeing_map, &tid, &ptr, BPF_ANY);
	return 0;
}

// ---- free exit: on success, resolve size, delete tracking, emit event ------
static __always_inline int cuda_free_exit(void *ctx, void *freeing_map,
					  void *sizes_map, __u8 is_runtime,
					  long ret)
{
	__u32 tid = cuda_tid();
	__u64 *ptrp = bpf_map_lookup_elem(freeing_map, &tid);
	if (!ptrp)
		return 0;
	__u64 ptr = *ptrp;
	bpf_map_delete_elem(freeing_map, &tid);

	if (ret != 0)		// free failed: leave tracking entry intact
		return 0;
	if (ptr == 0)		// free(NULL) is a valid no-op
		return 0;

	struct cuda_alloc_key k = {};
	k.pid = bpf_get_current_pid_tgid() >> 32;
	k.ptr = ptr;
	__u64 size = 0;
	__u64 *sp = bpf_map_lookup_elem(sizes_map, &k);
	if (sp)
		size = *sp;
	bpf_map_delete_elem(sizes_map, &k);

	if (!mep_proc_wanted())
		return 0;
	struct cuda_event *e = gadget_reserve_buf(&cuda_events, sizeof(*e));
	if (!e)
		return 0;
	e->timestamp_raw = bpf_ktime_get_boot_ns();
	gadget_process_populate(&e->proc);
	e->op_raw = cuda_free;
	e->is_runtime = is_runtime;
	e->size = size;
	e->ptr = ptr;
	e->retval = (__s64)ret;
	gadget_submit_buf(ctx, &cuda_events, e, sizeof(*e));
	return 0;
}

// ---- libcuda (driver API) : cuMemAlloc_v2 / cuMemFree_v2 -------------------
// CUresult cuMemAlloc_v2(CUdeviceptr *dptr, size_t bytesize)
SEC("uprobe/libcuda:cuMemAlloc_v2")
int BPF_UPROBE(mep_cu_alloc, void **dptr, size_t bytesize)
{
	return cuda_alloc_enter(&cuda_driver_pending, (__u64)dptr, (__u64)bytesize);
}

SEC("uretprobe/libcuda:cuMemAlloc_v2")
int BPF_URETPROBE(mep_cu_alloc_ret, long ret)
{
	return cuda_alloc_exit(ctx, &cuda_driver_pending, &cuda_driver_sizes, 0, ret);
}

// CUresult cuMemAllocAsync(CUdeviceptr *dptr, size_t bytesize, CUstream s)
SEC("uprobe/libcuda:cuMemAllocAsync")
int BPF_UPROBE(mep_cu_alloc_async, void **dptr, size_t bytesize)
{
	return cuda_alloc_enter(&cuda_driver_pending, (__u64)dptr, (__u64)bytesize);
}

SEC("uretprobe/libcuda:cuMemAllocAsync")
int BPF_URETPROBE(mep_cu_alloc_async_ret, long ret)
{
	return cuda_alloc_exit(ctx, &cuda_driver_pending, &cuda_driver_sizes, 0, ret);
}

// CUresult cuMemFree_v2(CUdeviceptr dptr)
SEC("uprobe/libcuda:cuMemFree_v2")
int BPF_UPROBE(mep_cu_free, u64 dptr)
{
	return cuda_free_enter(&cuda_driver_freeing, (__u64)dptr);
}

SEC("uretprobe/libcuda:cuMemFree_v2")
int BPF_URETPROBE(mep_cu_free_ret, long ret)
{
	return cuda_free_exit(ctx, &cuda_driver_freeing, &cuda_driver_sizes, 0, ret);
}

// CUresult cuMemFreeAsync(CUdeviceptr dptr, CUstream hStream)
SEC("uprobe/libcuda:cuMemFreeAsync")
int BPF_UPROBE(mep_cu_free_async, u64 dptr)
{
	return cuda_free_enter(&cuda_driver_freeing, (__u64)dptr);
}

SEC("uretprobe/libcuda:cuMemFreeAsync")
int BPF_URETPROBE(mep_cu_free_async_ret, long ret)
{
	return cuda_free_exit(ctx, &cuda_driver_freeing, &cuda_driver_sizes, 0, ret);
}

// ---- libcudart (runtime API) : cudaMalloc / cudaFree ----------------------
// cudaError_t cudaMalloc(void **devPtr, size_t size)
SEC("uprobe/libcudart:cudaMalloc")
int BPF_UPROBE(mep_cudart_alloc, void **devPtr, size_t size)
{
	return cuda_alloc_enter(&cuda_runtime_pending, (__u64)devPtr, (__u64)size);
}

SEC("uretprobe/libcudart:cudaMalloc")
int BPF_URETPROBE(mep_cudart_alloc_ret, long ret)
{
	return cuda_alloc_exit(ctx, &cuda_runtime_pending, &cuda_runtime_sizes, 1, ret);
}

// cudaError_t cudaMallocAsync(void **devPtr, size_t size, cudaStream_t s)
SEC("uprobe/libcudart:cudaMallocAsync")
int BPF_UPROBE(mep_cudart_alloc_async, void **devPtr, size_t size)
{
	return cuda_alloc_enter(&cuda_runtime_pending, (__u64)devPtr, (__u64)size);
}

SEC("uretprobe/libcudart:cudaMallocAsync")
int BPF_URETPROBE(mep_cudart_alloc_async_ret, long ret)
{
	return cuda_alloc_exit(ctx, &cuda_runtime_pending, &cuda_runtime_sizes, 1, ret);
}

// cudaError_t cudaFree(void *devPtr)
SEC("uprobe/libcudart:cudaFree")
int BPF_UPROBE(mep_cudart_free, u64 devPtr)
{
	return cuda_free_enter(&cuda_runtime_freeing, (__u64)devPtr);
}

SEC("uretprobe/libcudart:cudaFree")
int BPF_URETPROBE(mep_cudart_free_ret, long ret)
{
	return cuda_free_exit(ctx, &cuda_runtime_freeing, &cuda_runtime_sizes, 1, ret);
}

// cudaError_t cudaFreeAsync(void *devPtr, cudaStream_t stream)
SEC("uprobe/libcudart:cudaFreeAsync")
int BPF_UPROBE(mep_cudart_free_async, u64 devPtr)
{
	return cuda_free_enter(&cuda_runtime_freeing, (__u64)devPtr);
}

SEC("uretprobe/libcudart:cudaFreeAsync")
int BPF_URETPROBE(mep_cudart_free_async_ret, long ret)
{
	return cuda_free_exit(ctx, &cuda_runtime_freeing, &cuda_runtime_sizes, 1, ret);
}

// ===========================================================================
// capability: list_attachable -- iter/ksym enumerates kernel symbols from
// inside eBPF (no host-FS read). A name-prefix (ksym_filter) and kallsyms
// type-char (ksym_type) filter are applied in-kernel. Both are eBPF rodata
// params: declared const volatile + GADGET_PARAM(), so the ebpf operator
// populates them from the MCP call at load time -- no WASM needed for these.
// Emits via bpf_seq_write like every IG iterator.
// ===========================================================================

const volatile char ksym_filter[32] = {};
const volatile char ksym_type[2] = {};	// type[0]==0 => any type

GADGET_PARAM(ksym_filter);
GADGET_PARAM(ksym_type);

// ksym_max bounds how many matching symbols are emitted (0 == unlimited).
// kallsyms has ~300k entries on a stock kernel; an MCP client doing discovery
// rarely needs them all, and an unbounded enumeration produces a multi-MiB
// response. A small cap (e.g. 1000) keeps the result token-friendly while
// the prefix/type filters narrow WHICH symbols are returned. The cap is
// enforced in-kernel via a single-entry counter array so it holds across the
// iterator's per-symbol invocations.
const volatile __u32 ksym_max = 0;
GADGET_PARAM(ksym_max);

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} ksym_emitted SEC(".maps");

struct ksym_entry {
	__u64 addr;
	char type;
	char name[64];
	char module[56];
};

GADGET_ITER(symbols, ksym_entry, mep_ksym);

// Bounded prefix match (covers the dominant "vfs_*"/"tcp_*" discovery pattern).
// Empty filter matches everything. `name` is a bounded stack copy.
static __always_inline bool mep_name_prefix(const char *name)
{
	if (ksym_filter[0] == '\0')
		return true;
#pragma unroll
	for (int i = 0; i < 31; i++) {
		char f = ksym_filter[i];
		if (f == '\0')
			return true;	// whole prefix matched
		if (name[i] != f)
			return false;
	}
	return true;
}

SEC("iter/ksym")
int mep_ksym(struct bpf_iter__ksym *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct kallsym_iter *iter = ctx->ksym;
	if (iter == NULL)
		return 0;

	struct ksym_entry entry = {};
	entry.addr = iter->value;
	entry.type = iter->type;
	bpf_probe_read_kernel_str(entry.name, sizeof(entry.name), iter->name);
	bpf_probe_read_kernel_str(entry.module, sizeof(entry.module),
				  iter->module_name);

	if (ksym_type[0] != '\0') {
		// kallsyms lowercases file-local symbols; accept either case so a
		// request for 't' also returns 'T' (global text).
		char t = entry.type;
		char tl = (t >= 'A' && t <= 'Z') ? t - 'A' + 'a' : t;
		char w = ksym_type[0];
		char wl = (w >= 'A' && w <= 'Z') ? w - 'A' + 'a' : w;
		if (tl != wl)
			return 0;
	}

	if (!mep_name_prefix(entry.name))
		return 0;

	// Skip GCC/LTO optimizer-clone symbols (".constprop.N", ".isra.N", ".cold",
	// ".part.N", ".llvm.HASH"). They ARE present in kallsyms but the kernel
	// kprobe_events parser rejects a '.' in the probe target with -EINVAL, so
	// advertising them via list_attachable only yields an opaque
	// "write /sys/kernel/tracing/kprobe_events: invalid argument" -32603 when an
	// client later attaches one (e.g. __alloc_pages_slowpath
	//.constprop.0). A '.' in a kernel symbol name is the unambiguous marker of
	// such a non-attachable clone -- legitimate kprobe-able symbols never carry
	// one -- so filter them at the producer (bounded scan of the stack copy).
#pragma unroll
	for (int di = 0; di < (int)sizeof(entry.name); di++) {
		if (entry.name[di] == '\0')
			break;
		if (entry.name[di] == '.')
			return 0;
	}

	// Enforce the optional emit cap. Read-modify-write of a single array slot;
	// the ksym iterator is single-threaded per seq_file walk so no atomics are
	// needed for a best-effort bound.
	if (ksym_max != 0) {
		__u32 zero = 0;
		__u32 *n = bpf_map_lookup_elem(&ksym_emitted, &zero);
		if (n == NULL)
			return 0;
		if (*n >= ksym_max)
			return 0;
		*n += 1;
	}

	bpf_seq_write(seq, &entry, sizeof(entry));
	return 0;
}

// ============================ [sock_snapshot] sock_snapshot ============================
// Point-in-time per-socket TCP snapshot (ss(8)-in-eBPF) via the in-kernel TCP
// iterator (SEC iter/tcp). The kprobe/tracepoint families see EVENTS as they
// fire; this instead walks EVERY live TCP socket on demand and emits its
// CURRENT state + timers + queue depths, answering questions no event stream
// can: "ESTABLISHED but 64 KB stuck in the send-Q and rising" (peer not ACKing
// / app write-blocked) vs "0 bytes queued, idle 30 s" (healthy-idle). The
// 4-tuple/state/family come straight off struct sock_common (shared by full,
// TIME_WAIT and request socks) so per_conn_identity (per_conn_identity) holds for every row
// uniformly. ss-detail (srtt/rto/retransmits/cwnd/queues) is read ONLY off a
// full struct tcp_sock*; mini-socks (TIME_WAIT / NEW_SYN_RECV) carry none, so
// touching tcp_sock detail on them would be a memory-safety bug -- they emit the
// 4-tuple + state with detail zeroed and sock_kind marking which kind it was.
struct socksnap_entry {
	__u32 saddr;		// local IPv4 (network order, like mep_sockstate.saddr)
	__u32 daddr;		// remote IPv4 (network order)
	__u16 sport;		// local port (host order)
	__u16 dport;		// remote port (host order)
	__u16 family;		// AF_INET(2) / AF_INET6(10)
	__u16 state;		// current TCP state (1=ESTABLISHED..12=NEW_SYN_RECV)
	__u32 netns_id;		// network namespace inode id
	__u8  sock_kind;	// 1=full tcp_sock, 2=TIME_WAIT, 3=request(SYN_RECV half-open)
	__u32 srtt_us;		// [full] smoothed RTT (tp->srtt_us, raw usec>>3)
	__u32 rto;		// [full] icsk_rto -- retransmission timeout (raw)
	__u32 retransmits;	// [full] icsk_retransmits -- current backoff count (>0 = stuck retransmitting)
	__u32 snd_cwnd;		// [full] congestion window (segments)
	__u32 sndq_bytes;	// [full] sk_wmem_queued -- bytes in the send queue right now
	__u32 unacked_bytes;	// [full] write_seq - snd_una -- sent-but-unACKed (in flight)
	__u32 rcvq_bytes;	// [full] rcv_nxt - copied_seq -- received-but-unread by the app
	__u64 last_snd_ts;	// [full] tp->lsndtime -- for "idle for N" reasoning
};

GADGET_ITER(mep_socksnap, socksnap_entry, mep_socksnap);

SEC("iter/tcp")
int mep_socksnap(struct bpf_iter__tcp *ctx)
{
	struct sock_common *skc = ctx->sk_common;
	struct seq_file *seq = ctx->meta->seq;
	struct socksnap_entry e = {};
	__u32 netns = 0;

	if (skc == NULL)
		return 0;

	// 4-tuple + state + family off sock_common -- valid for full, TIME_WAIT
	// and request socks alike (per_conn_identity, per_conn_identity, threaded here too).
	e.saddr  = BPF_CORE_READ(skc, skc_rcv_saddr);
	e.daddr  = BPF_CORE_READ(skc, skc_daddr);
	e.sport  = BPF_CORE_READ(skc, skc_num);			// already host order
	e.dport  = bpf_ntohs(BPF_CORE_READ(skc, skc_dport));	// net -> host
	e.family = BPF_CORE_READ(skc, skc_family);
	e.state  = BPF_CORE_READ(skc, skc_state);
	BPF_CORE_READ_INTO(&netns, skc, skc_net.net, ns.inum);
	e.netns_id = netns;

	// Only full sockets carry a struct tcp_sock with the ss-detail fields.
	struct tcp_sock *tp = bpf_skc_to_tcp_sock(skc);
	if (tp) {
		__u32 write_seq, snd_una, rcv_nxt, copied_seq;
		e.sock_kind   = 1;
		e.srtt_us     = BPF_CORE_READ(tp, srtt_us);
		e.snd_cwnd    = BPF_CORE_READ(tp, snd_cwnd);
		e.last_snd_ts = BPF_CORE_READ(tp, lsndtime);
		e.rto         = BPF_CORE_READ(tp, inet_conn.icsk_rto);
		e.retransmits = BPF_CORE_READ(tp, inet_conn.icsk_retransmits);
		e.sndq_bytes  = BPF_CORE_READ(tp, inet_conn.icsk_inet.sk.sk_wmem_queued);
		write_seq  = BPF_CORE_READ(tp, write_seq);
		snd_una    = BPF_CORE_READ(tp, snd_una);
		rcv_nxt    = BPF_CORE_READ(tp, rcv_nxt);
		copied_seq = BPF_CORE_READ(tp, copied_seq);
		e.unacked_bytes = write_seq - snd_una;
		e.rcvq_bytes    = rcv_nxt - copied_seq;
	} else if (bpf_skc_to_tcp_timewait_sock(skc)) {
		e.sock_kind = 2;	// TIME_WAIT -- detail stays zeroed
	} else if (bpf_skc_to_tcp_request_sock(skc)) {
		e.sock_kind = 3;	// NEW_SYN_RECV half-open -- detail stays zeroed
	}

	bpf_seq_write(seq, &e, sizeof(e));
	return 0;
}
// ========================== [end sock_snapshot] sock_snapshot =========================



// ===========================================================================
// capability: cuda_profile -- CUDA GPU *activity* profiling via uprobes on the
// driver (libcuda) launch / sync / host<->device copy entry points. Where
// cuda_memtrace answers "is GPU memory leaking", cuda_profile answers "is the
// GPU actually busy, and where is time going" — GPU occupancy/right-
// sizing and PCIe-bound questions. It enriches each call with the SUBSYSTEM-
// SPECIFIC arguments an MCP client needs:
// - cuLaunchKernel / cuLaunchKernelEx : grid (gx,gy,gz) and block (bx,by,bz)
// dimensions -> threads-per-launch, so an MCP client can see launch RATE and
// occupancy intent without reading SM counters.
// - cuMemcpyHtoD/DtoH(_Async)_v2 : transfer byteCount + direction, so an
// client can see PCIe H2D/D2H volume and spot a copy-bound workload.
// - cuStreamSynchronize/cuCtxSynchronize : a SYNC barrier with a measured
// wall-clock DURATION (uprobe->uretprobe delta) -> host-side GPU wait time.
// Each event carries op, the decoded args, and (for sync) duration_ns. This is
// the launch/stall/transfer signal, correlated externally with an
// NVML SM%/mem% sample. READ-ONLY: pure ABI observation.
// ===========================================================================

enum cuprof_op {
	cuprof_launch,		// cuLaunchKernel(Ex): grid/block dims in arg fields
	cuprof_sync,		// cuStreamSynchronize/cuCtxSynchronize: duration_ns set
	cuprof_memcpy_h2d,	// cuMemcpyHtoD(_Async)_v2: bytes set
	cuprof_memcpy_d2h,	// cuMemcpyDtoH(_Async)_v2: bytes set
};

struct cuprof_event {
	gadget_timestamp timestamp_raw;
	struct gadget_process proc;

	enum cuprof_op gpu_op_raw;
	__u32 gx, gy, gz;	// grid dims (launch)
	__u32 bx, by, bz;	// block dims (launch)
	__u64 bytes;		// transfer size (memcpy)
	gadget_duration duration_ns;	// wall-clock of the call (sync); 0 otherwise
	__s64 retval;		// CUDA return code (0 == CUDA_SUCCESS)
};

GADGET_TRACER_MAP(cuprof_events, 1024 * 256);
GADGET_TRACER(mep_cuprof, cuprof_events, cuprof_event);

// per-tid scratch carrying the sync call's entry timestamp so the uretprobe can
// compute its wall-clock duration. Keyed by tid because concurrent host threads
// can each be blocked in a different sync at once.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);	// tid
	__type(value, __u64);	// entry ktime_ns
} cuprof_sync_enter SEC(".maps");

// --- cuda_profile server-side op-class filter -----------
// cuda_profile multiplexes FOUR op classes onto one cuprof_events ring:
// cuprof_launch (cuLaunchKernel*), cuprof_sync, cuprof_memcpy_h2d/d2h.
// On a busy GPU box the kernel-LAUNCH stream dominates: a single closed-loop
// PCIe-bottleneck repro emitted 115278 cuprof_launch rows vs only 646 memcpy
// H2D/D2H rows (0.56%). Those rare copy rows — the ONLY ones carrying the H2D
// byte volume that proves a PCIe copy bottleneck — get truncated out of the MCP
// result window, so the MCP client sees only bytes:0 launch rows and cannot name the
// mechanism (validated end-to-end: cuda_profile returned
// isTruncated=true, 0 memcpy rows surfaced). This mirrors the proven fs_op fix:
// let the MCP client isolate ONE op class in-kernel so the diagnostic survives.
// copy : keep only memcpy_h2d + memcpy_d2h (the PCIe transfer rows)
// launch: keep only kernel launches
// sync : keep only stream/ctx synchronize
// Empty/all == keep every class (default, a no-op for the other consumers).
#define CUDA_OP_FILTER_ALL    0
#define CUDA_OP_FILTER_LAUNCH 1
#define CUDA_OP_FILTER_SYNC   2
#define CUDA_OP_FILTER_COPY   3
#define CUDA_OP_FILTER_H2D    4
#define CUDA_OP_FILTER_D2H    5
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} filter_cuda_op SEC(".maps");

static __always_inline bool cuprof_emit_wanted(enum cuprof_op op)
{
	__u32 k = 0;
	__u64 *f = bpf_map_lookup_elem(&filter_cuda_op, &k);
	if (!f || *f == CUDA_OP_FILTER_ALL)
		return true;
	if (*f == CUDA_OP_FILTER_COPY)
		return op == cuprof_memcpy_h2d || op == cuprof_memcpy_d2h;
	if (*f == CUDA_OP_FILTER_H2D)
		return op == cuprof_memcpy_h2d;
	if (*f == CUDA_OP_FILTER_D2H)
		return op == cuprof_memcpy_d2h;
	if (*f == CUDA_OP_FILTER_LAUNCH)
		return op == cuprof_launch;
	if (*f == CUDA_OP_FILTER_SYNC)
		return op == cuprof_sync;
	return true;
}

static __always_inline struct cuprof_event *cuprof_new(enum cuprof_op op)
{
	if (!mep_proc_wanted())
		return 0;
	if (!cuprof_emit_wanted(op))
		return 0;
	struct cuprof_event *e = gadget_reserve_buf(&cuprof_events, sizeof(*e));
	if (!e)
		return 0;
	e->timestamp_raw = bpf_ktime_get_boot_ns();
	gadget_process_populate(&e->proc);
	e->gpu_op_raw = op;
	e->gx = e->gy = e->gz = 0;
	e->bx = e->by = e->bz = 0;
	e->bytes = 0;
	e->duration_ns = 0;
	e->retval = 0;
	return e;
}

// CUresult cuLaunchKernel(CUfunction f, uint gx, uint gy, uint gz,
// uint bx, uint by, uint bz, uint shmem,
// CUstream s, void **params, void **extra)
// Args: PARM2..PARM7 carry the 6 grid/block dims (PARM1 = the function handle).
SEC("uprobe/libcuda:cuLaunchKernel")
int BPF_UPROBE(mep_cuprof_launch)
{
	struct cuprof_event *e = cuprof_new(cuprof_launch);
	if (!e)
		return 0;
	e->gx = (__u32)PT_REGS_PARM2(ctx);
	e->gy = (__u32)PT_REGS_PARM3(ctx);
	e->gz = (__u32)PT_REGS_PARM4(ctx);
	e->bx = (__u32)PT_REGS_PARM5(ctx);
	e->by = (__u32)PT_REGS_PARM6(ctx);
	// 7th integer arg (gridDimZ block? no: blockDimZ) is on the stack in the
	// SysV ABI (only 6 GPRs for integer args); read it from the user stack.
	// stack layout at uprobe entry: [ret_addr][arg7][arg8]... so arg7 (bz) is
	// at sp+8. Best-effort; failure leaves bz=0.
	__u64 sp = PT_REGS_SP(ctx);
	__u32 bz = 0;
	bpf_probe_read_user(&bz, sizeof(bz), (void *)(sp + 8));
	e->bz = bz;
	gadget_submit_buf(ctx, &cuprof_events, e, sizeof(*e));
	return 0;
}

// cuLaunchKernelEx(const CUlaunchConfig *cfg, CUfunction f, void **params,
// void **extra) — grid/block live inside *cfg. We record the
// launch event (dims read from the config struct: gridDimX/Y/Z then
// blockDimX/Y/Z are the first 6 uints of CUlaunchConfig).
SEC("uprobe/libcuda:cuLaunchKernelEx")
int BPF_UPROBE(mep_cuprof_launch_ex, void *cfg)
{
	struct cuprof_event *e = cuprof_new(cuprof_launch);
	if (!e)
		return 0;
	if (cfg) {
		__u32 dims[6] = {};
		bpf_probe_read_user(dims, sizeof(dims), cfg);
		e->gx = dims[0]; e->gy = dims[1]; e->gz = dims[2];
		e->bx = dims[3]; e->by = dims[4]; e->bz = dims[5];
	}
	gadget_submit_buf(ctx, &cuprof_events, e, sizeof(*e));
	return 0;
}

// ---- sync: measure host-side GPU wait (enter ts -> exit ts) ----------------
static __always_inline int cuprof_sync_enter_fn(void)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	__u64 ts = bpf_ktime_get_boot_ns();
	bpf_map_update_elem(&cuprof_sync_enter, &tid, &ts, BPF_ANY);
	return 0;
}

static __always_inline int cuprof_sync_exit_fn(void *ctx, long ret)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	__u64 *tsp = bpf_map_lookup_elem(&cuprof_sync_enter, &tid);
	if (!tsp)
		return 0;
	__u64 dur = bpf_ktime_get_boot_ns() - *tsp;
	bpf_map_delete_elem(&cuprof_sync_enter, &tid);

	struct cuprof_event *e = cuprof_new(cuprof_sync);
	if (!e)
		return 0;
	e->duration_ns = dur;
	e->retval = (__s64)ret;
	gadget_submit_buf(ctx, &cuprof_events, e, sizeof(*e));
	return 0;
}

SEC("uprobe/libcuda:cuStreamSynchronize")
int BPF_UPROBE(mep_cuprof_streamsync) { return cuprof_sync_enter_fn(); }
SEC("uretprobe/libcuda:cuStreamSynchronize")
int BPF_URETPROBE(mep_cuprof_streamsync_ret, long ret) { return cuprof_sync_exit_fn(ctx, ret); }

SEC("uprobe/libcuda:cuCtxSynchronize")
int BPF_UPROBE(mep_cuprof_ctxsync) { return cuprof_sync_enter_fn(); }
SEC("uretprobe/libcuda:cuCtxSynchronize")
int BPF_URETPROBE(mep_cuprof_ctxsync_ret, long ret) { return cuprof_sync_exit_fn(ctx, ret); }

// ---- memcpy: record direction + byteCount ----------------------------------
// CUresult cuMemcpyHtoD_v2(CUdeviceptr dst, const void *src, size_t ByteCount)
// -> ByteCount is PARM3
// CUresult cuMemcpyHtoDAsync_v2(CUdeviceptr dst, const void *src,
// size_t ByteCount, CUstream s) -> PARM3
SEC("uprobe/libcuda:cuMemcpyHtoD_v2")
int BPF_UPROBE(mep_cuprof_h2d, u64 dst, void *src, u64 bytes)
{
	struct cuprof_event *e = cuprof_new(cuprof_memcpy_h2d);
	if (!e) return 0;
	e->bytes = bytes;
	gadget_submit_buf(ctx, &cuprof_events, e, sizeof(*e));
	return 0;
}
SEC("uprobe/libcuda:cuMemcpyHtoDAsync_v2")
int BPF_UPROBE(mep_cuprof_h2d_async, u64 dst, void *src, u64 bytes)
{
	struct cuprof_event *e = cuprof_new(cuprof_memcpy_h2d);
	if (!e) return 0;
	e->bytes = bytes;
	gadget_submit_buf(ctx, &cuprof_events, e, sizeof(*e));
	return 0;
}
// CUresult cuMemcpyDtoH_v2(void *dstHost, CUdeviceptr src, size_t ByteCount)
SEC("uprobe/libcuda:cuMemcpyDtoH_v2")
int BPF_UPROBE(mep_cuprof_d2h, void *dst, u64 src, u64 bytes)
{
	struct cuprof_event *e = cuprof_new(cuprof_memcpy_d2h);
	if (!e) return 0;
	e->bytes = bytes;
	gadget_submit_buf(ctx, &cuprof_events, e, sizeof(*e));
	return 0;
}
SEC("uprobe/libcuda:cuMemcpyDtoHAsync_v2")
int BPF_UPROBE(mep_cuprof_d2h_async, void *dst, u64 src, u64 bytes)
{
	struct cuprof_event *e = cuprof_new(cuprof_memcpy_d2h);
	if (!e) return 0;
	e->bytes = bytes;
	gadget_submit_buf(ctx, &cuprof_events, e, sizeof(*e));
	return 0;
}


// ===========================================================================
// capability: lock_trace -- userspace lock CONTENTION via uprobes on the libc
// pthread synchronization primitives, measuring the WALL-CLOCK time each thread
// spends BLOCKED. This is the userspace lock-contention signal:
// - pthread_mutex_lock(m) : uprobe->uretprobe delta = time spent
// waiting to ACQUIRE the mutex (the contention cost). addr = &m.
// - pthread_cond_wait(c, m) : delta = time blocked on the condvar. addr = &c.
// - pthread_cond_timedwait(c,m,t): same, bounded by the caller's timeout.
// An uncontended lock returns in tens of nanoseconds; a contended one shows
// micro/millisecond waits, and the addr column lets an MCP client see that the waits
// concentrate on ONE lock. We deliberately do NOT trace the (instantaneous)
// unlock — the blocked-acquire duration is the contention signal. READ-ONLY.
// ===========================================================================

enum lock_op {
	lock_mutex_wait,	// pthread_mutex_lock: duration = acquire wait
	lock_cond_wait,		// pthread_cond_wait/timedwait: duration = blocked time
	lock_futex_wait,	// kernel futex(FUTEX_WAIT*): duration = blocked-in-kernel time
};

struct lock_event {
	gadget_timestamp timestamp_raw;
	struct gadget_process proc;

	enum lock_op lock_op_raw;
	__u64 addr;		// mutex/cond object pointer (groups waits by lock)
	gadget_duration duration_ns;	// time spent blocked in the call
	__u32 holder_tid;	// TID holding `addr` when this waiter blocked (0=unknown)
	__s64 retval;		// pthread return (0 == success)
};

GADGET_TRACER_MAP(lock_events, 1024 * 256);
GADGET_TRACER(mep_lock, lock_events, lock_event);

// per-tid scratch carrying (entry ts, lock addr) from uprobe -> uretprobe.
struct lock_pending {
	__u64 ts;
	__u64 addr;
	enum lock_op op;
	__u32 holder;	// current holder of addr, sampled at enter
};

// addr -> TID currently holding that mutex. Populated by watching the
// actual pthread_mutex_lock acquire / pthread_mutex_unlock release uprobes, so
// it is correct for PTHREAD_MUTEX_NORMAL too (no glibc-internal __owner read).
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, __u64);	// lock object address
	__type(value, __u32);	// holder tid
} lock_holder_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, __u32);	// tid
	__type(value, struct lock_pending);
} lock_pending_map SEC(".maps");

static __always_inline int lock_enter(enum lock_op op, __u64 addr)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	struct lock_pending p = {};
	p.ts = bpf_ktime_get_boot_ns();
	p.addr = addr;
	p.op = op;
	// who holds this lock right now? That is the contention culprit the
	// blocked waiter is stuck behind. 0 if uncontended / first acquire.
	__u32 *h = bpf_map_lookup_elem(&lock_holder_map, &addr);
	p.holder = h ? *h : 0;
	bpf_map_update_elem(&lock_pending_map, &tid, &p, BPF_ANY);
	return 0;
}

static __always_inline int lock_exit(void *ctx, long ret)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	struct lock_pending *p = bpf_map_lookup_elem(&lock_pending_map, &tid);
	if (!p)
		return 0;
	__u64 dur = bpf_ktime_get_boot_ns() - p->ts;
	__u64 addr = p->addr;
	enum lock_op op = p->op;
	bpf_map_delete_elem(&lock_pending_map, &tid);

	if (!mep_proc_wanted())
		return 0;
	struct lock_event *e = gadget_reserve_buf(&lock_events, sizeof(*e));
	if (!e)
		return 0;
	e->timestamp_raw = bpf_ktime_get_boot_ns();
	gadget_process_populate(&e->proc);
	e->lock_op_raw = op;
	e->addr = addr;
	e->duration_ns = dur;
	e->holder_tid = p->holder;	// who we were blocked behind
	e->retval = (__s64)ret;
	gadget_submit_buf(ctx, &lock_events, e, sizeof(*e));
	// on a successful mutex acquire we are now the holder; record it so
	// the NEXT waiter on this addr can attribute its block to us.
	if (ret == 0 && op == lock_mutex_wait) {
		__u32 me = tid;
		bpf_map_update_elem(&lock_holder_map, &addr, &me, BPF_ANY);
	}
	return 0;
}

// int pthread_mutex_lock(pthread_mutex_t *mutex) — PARM1 = &mutex
SEC("uprobe/libc:pthread_mutex_lock")
int BPF_UPROBE(mep_lock_mutex, void *mutex)
{
	return lock_enter(lock_mutex_wait, (__u64)mutex);
}
SEC("uretprobe/libc:pthread_mutex_lock")
int BPF_URETPROBE(mep_lock_mutex_ret, long ret) { return lock_exit(ctx, ret); }

// pthread_mutex_unlock(&m) — releaser clears the holder for addr so a
// later waiter does not mis-attribute its block to a stale owner.
SEC("uprobe/libc:pthread_mutex_unlock")
int BPF_UPROBE(mep_lock_unlock, void *mutex)
{
	__u64 addr = (__u64)mutex;
	__u32 zero = 0;
	bpf_map_update_elem(&lock_holder_map, &addr, &zero, BPF_ANY);
	return 0;
}

// int pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex) — PARM1 = &cond
SEC("uprobe/libc:pthread_cond_wait")
int BPF_UPROBE(mep_lock_cond, void *cond)
{
	return lock_enter(lock_cond_wait, (__u64)cond);
}
SEC("uretprobe/libc:pthread_cond_wait")
int BPF_URETPROBE(mep_lock_cond_ret, long ret) { return lock_exit(ctx, ret); }

SEC("uprobe/libc:pthread_cond_timedwait")
int BPF_UPROBE(mep_lock_condt, void *cond)
{
	return lock_enter(lock_cond_wait, (__u64)cond);
}
SEC("uretprobe/libc:pthread_cond_timedwait")
int BPF_URETPROBE(mep_lock_condt_ret, long ret) { return lock_exit(ctx, ret); }

// ---------------------------------------------------------------------------
// lock_trace EXPANSION (directive-22124/22126): kernel futex(FUTEX_WAIT*) hook.
// pthread mutex/cond CONTENTION blocks in the kernel via the futex syscall. The
// libc uprobes above can miss waits when the target's libc symbol fails to
// resolve or attaches after the contention burst; the futex syscall ALWAYS runs
// in the contending thread's OWN process context, so mep_proc_wanted() (the
// shared filter_pid gate) attributes it to the subject deterministically. We
// time only the BLOCKING wait ops (FUTEX_WAIT / FUTEX_WAIT_BITSET); wakes and
// requeues are instantaneous and excluded. addr = uaddr groups waits per lock.
// READ-ONLY: pure syscall-arg + return observation. Uses a DEDICATED pending
// map so a contended mutex's inner futex cannot clobber the uprobe pending slot.
// ---------------------------------------------------------------------------
#define MEP_FUTEX_WAIT		0
#define MEP_FUTEX_WAIT_BITSET	9
#define MEP_FUTEX_CMD_MASK	0x7f	// strip FUTEX_PRIVATE_FLAG|FUTEX_CLOCK_REALTIME

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, __u32);	// tid
	__type(value, struct lock_pending);
} lock_futex_pending_map SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_futex")
int mep_lock_futex_enter(struct trace_event_raw_sys_enter *ctx)
{
	int cmd = (int)ctx->args[1] & MEP_FUTEX_CMD_MASK;
	if (cmd != MEP_FUTEX_WAIT && cmd != MEP_FUTEX_WAIT_BITSET)
		return 0;
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	struct lock_pending p = {};
	p.ts = bpf_ktime_get_boot_ns();
	p.addr = (__u64)ctx->args[0];	// uaddr (the lock/cond futex word)
	p.op = lock_futex_wait;
	// (futex path): the contended pthread mutex blocks here in the
	// kernel. Sample who currently holds uaddr (recorded by the
	// pthread_mutex_lock uretprobe on a successful acquire) so this blocked
	// waiter can attribute its stall to the owning thread. 0 if unknown.
	__u32 *fh = bpf_map_lookup_elem(&lock_holder_map, &p.addr);
	p.holder = fh ? *fh : 0;
	bpf_map_update_elem(&lock_futex_pending_map, &tid, &p, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_futex")
int mep_lock_futex_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	struct lock_pending *p = bpf_map_lookup_elem(&lock_futex_pending_map, &tid);
	if (!p)
		return 0;
	__u64 dur = bpf_ktime_get_boot_ns() - p->ts;
	__u64 addr = p->addr;
	bpf_map_delete_elem(&lock_futex_pending_map, &tid);

	if (!mep_proc_wanted())
		return 0;
	struct lock_event *e = gadget_reserve_buf(&lock_events, sizeof(*e));
	if (!e)
		return 0;
	e->timestamp_raw = bpf_ktime_get_boot_ns();
	gadget_process_populate(&e->proc);
	e->lock_op_raw = lock_futex_wait;
	e->addr = addr;
	e->duration_ns = dur;
	e->holder_tid = p->holder;	// thread we were blocked behind
	e->retval = (__s64)ctx->ret;
	gadget_submit_buf(ctx, &lock_events, e, sizeof(*e));
	return 0;
}

// ===========================================================================
// capability: heap_profile -- userspace HEAP churn/leak via uprobes on the
// libc allocator (malloc/calloc/realloc/free), emitting one event per call with
// the requested size and the returned/freed pointer. This is the
// userspace allocation signal at the C-library layer (the counterpart of
// cuda_memtrace for host RAM): an MCP client reconciles alloc/free pairs to see
// - churn : a high malloc+free RATE on the hot path (alloc==free, but huge), and
// - leak : a sustained alloc>free imbalance (live bytes climbing).
// size is taken at uprobe entry (the request); ptr at uretprobe (the result),
// matched per-tid. free carries the freed ptr (size unknown at libc layer, so
// reconciliation is by ptr identity). READ-ONLY: pure allocator-ABI observation.
// ===========================================================================

enum heap_op {
	heap_malloc,
	heap_calloc,
	heap_realloc,
	heap_free,
	heap_brk_grow,	// kernel sys_exit_brk: heap (brk) high-water GREW by `size` bytes
	heap_mmap_anon,	// kernel sys_enter_mmap(MAP_ANONYMOUS,fd<0): anon mapping of `size` bytes
	heap_mmap_file,	// kernel sys_enter_mmap(fd>=0): file-backed mapping of `size` bytes (page-cache / address-space growth)
};

struct heap_event {
	gadget_timestamp timestamp_raw;
	struct gadget_process proc;

	enum heap_op heap_op_raw;
	__u64 size;	// requested bytes (alloc family); 0 for free
	__u64 ptr;	// returned ptr (alloc) or freed ptr (free)
	__u64 old_ptr;	// realloc: the pointer being resized; 0 otherwise
};

GADGET_TRACER_MAP(heap_events, 1024 * 256);
GADGET_TRACER(mep_heap, heap_events, heap_event);

// per-tid scratch carrying (op, size, old_ptr) from alloc uprobe -> uretprobe.
struct heap_pending {
	enum heap_op op;
	__u64 size;
	__u64 old_ptr;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, __u32);	// tid
	__type(value, struct heap_pending);
} heap_pending_map SEC(".maps");

static __always_inline int heap_alloc_enter(enum heap_op op, __u64 size, __u64 old_ptr)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	struct heap_pending p = {};
	p.op = op;
	p.size = size;
	p.old_ptr = old_ptr;
	bpf_map_update_elem(&heap_pending_map, &tid, &p, BPF_ANY);
	return 0;
}

static __always_inline int heap_alloc_exit(void *ctx, long ret)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	struct heap_pending *p = bpf_map_lookup_elem(&heap_pending_map, &tid);
	if (!p)
		return 0;
	enum heap_op op = p->op;
	__u64 size = p->size;
	__u64 old_ptr = p->old_ptr;
	bpf_map_delete_elem(&heap_pending_map, &tid);

	if (!mep_proc_wanted())
		return 0;
	struct heap_event *e = gadget_reserve_buf(&heap_events, sizeof(*e));
	if (!e)
		return 0;
	e->timestamp_raw = bpf_ktime_get_boot_ns();
	gadget_process_populate(&e->proc);
	e->heap_op_raw = op;
	e->size = size;
	e->ptr = (__u64)ret;
	e->old_ptr = old_ptr;
	gadget_submit_buf(ctx, &heap_events, e, sizeof(*e));
	return 0;
}

// void *malloc(size_t size) — PARM1 = size
SEC("uprobe/libc:malloc")
int BPF_UPROBE(mep_heap_malloc, u64 size)
{
	return heap_alloc_enter(heap_malloc, size, 0);
}
SEC("uretprobe/libc:malloc")
int BPF_URETPROBE(mep_heap_malloc_ret, long ret) { return heap_alloc_exit(ctx, ret); }

// void *calloc(size_t nmemb, size_t size) — bytes = nmemb*size
SEC("uprobe/libc:calloc")
int BPF_UPROBE(mep_heap_calloc, u64 nmemb, u64 size)
{
	return heap_alloc_enter(heap_calloc, nmemb * size, 0);
}
SEC("uretprobe/libc:calloc")
int BPF_URETPROBE(mep_heap_calloc_ret, long ret) { return heap_alloc_exit(ctx, ret); }

// void *realloc(void *ptr, size_t size) — PARM1 = old ptr, PARM2 = size
SEC("uprobe/libc:realloc")
int BPF_UPROBE(mep_heap_realloc, u64 old_ptr, u64 size)
{
	return heap_alloc_enter(heap_realloc, size, old_ptr);
}
SEC("uretprobe/libc:realloc")
int BPF_URETPROBE(mep_heap_realloc_ret, long ret) { return heap_alloc_exit(ctx, ret); }

// void free(void *ptr) — PARM1 = ptr; emit immediately (no return value)
SEC("uprobe/libc:free")
int BPF_UPROBE(mep_heap_free, u64 ptr)
{
	if (ptr == 0)	// free(NULL) is a no-op
		return 0;
	if (!mep_proc_wanted())
		return 0;
	struct heap_event *e = gadget_reserve_buf(&heap_events, sizeof(*e));
	if (!e)
		return 0;
	e->timestamp_raw = bpf_ktime_get_boot_ns();
	gadget_process_populate(&e->proc);
	e->heap_op_raw = heap_free;
	e->size = 0;
	e->ptr = ptr;
	e->old_ptr = 0;
	gadget_submit_buf(ctx, &heap_events, e, sizeof(*e));
	return 0;
}

// ---------------------------------------------------------------------------
// HOST-VISIBLE heap growth via KERNEL syscall tracepoints (additive).
// The libc malloc/free uprobes above are attached by IG's uprobetracer, which
// is CONTAINER-SCOPED: it only attaches inside enumerated containers, so a
// a workload running on the HOST (a process launched directly,
// outside any container) is never an attach target and the libc uprobes emit ZERO
// rows for it (proven: `attach_uprobe libc:malloc --pid=<host-pid>` returned 36
// rows, ALL from containerd-shim/dcgm-exporter, none from the host leaker pid).
// The brk()/mmap() syscalls ALWAYS run in the allocating thread's OWN process
// context, so mep_proc_wanted() (the shared filter_pid gate) attributes them to
// the host subject deterministically — exactly the idiom the lock_trace futex
// tracepoint uses to escape the same uprobe-scoping fragility. READ-ONLY: pure
// syscall return/arg observation. These complement (do not replace) the libc
// uprobes, which still serve containerized targets.
// ---------------------------------------------------------------------------
#define MEP_MAP_ANONYMOUS 0x20	// linux/mman.h MAP_ANONYMOUS (x86_64)

// per-tgid heap (program break) high-water, to emit only GROWTH deltas. LRU so
// a flood of short-lived pids can never exhaust it.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, __u32);	// tgid
	__type(value, __u64);	// last observed program break
} heap_brk_map SEC(".maps");

// brk(2): the userspace allocator's small-object arena grows by moving the
// program break up. ret = the new break (or the current one on query). We track
// the per-tgid high-water and emit one heap_brk_grow event carrying the byte
// delta whenever it climbs — the classic host-RAM leak/churn signature.
SEC("tracepoint/syscalls/sys_exit_brk")
int mep_heap_brk(struct trace_event_raw_sys_exit *ctx)
{
	__u64 newbrk = (__u64)ctx->ret;
	if (newbrk == 0)
		return 0;
	__u32 tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
	__u64 *last = bpf_map_lookup_elem(&heap_brk_map, &tgid);
	__u64 prev = last ? *last : 0;
	bpf_map_update_elem(&heap_brk_map, &tgid, &newbrk, BPF_ANY);
	if (prev == 0 || newbrk <= prev)	// first sighting or shrink: record only
		return 0;
	if (!mep_proc_wanted())
		return 0;
	struct heap_event *e = gadget_reserve_buf(&heap_events, sizeof(*e));
	if (!e)
		return 0;
	e->timestamp_raw = bpf_ktime_get_boot_ns();
	gadget_process_populate(&e->proc);
	e->heap_op_raw = heap_brk_grow;
	e->size = newbrk - prev;	// bytes the heap arena grew
	e->ptr = newbrk;
	e->old_ptr = prev;
	gadget_submit_buf(ctx, &heap_events, e, sizeof(*e));
	return 0;
}

// mmap(2): large allocations (> M_MMAP_THRESHOLD, default 128 KiB) bypass brk
// and come straight from anonymous mmap. We record anonymous, non-file-backed
// mappings (the heap-relevant ones) with their requested length.
SEC("tracepoint/syscalls/sys_enter_mmap")
int mep_heap_mmap(struct trace_event_raw_sys_enter *ctx)
{
	__u64 len   = (__u64)ctx->args[1];
	__u64 flags = (__u64)ctx->args[3];
	// fd arrives as a 32-bit value zero-extended into the 64-bit arg slot, so an
	// anonymous mmap's fd=-1 reads as 0xFFFFFFFF; truncate to int so the sign is
	// preserved (a (long) cast would make -1 look like +4294967295 and wrongly
	// classify every anon mapping as file-backed).
	int   fd    = (int)ctx->args[4];
	if (!(flags & MEP_MAP_ANONYMOUS)) {	// file-backed mapping (fd>=0): page-cache / address-space signal
		if (fd < 0 || len == 0)
			return 0;
		if (!mep_proc_wanted())
			return 0;
		struct heap_event *fe = gadget_reserve_buf(&heap_events, sizeof(*fe));
		if (!fe)
			return 0;
		fe->timestamp_raw = bpf_ktime_get_boot_ns();
		gadget_process_populate(&fe->proc);
		fe->heap_op_raw = heap_mmap_file;
		fe->size = len;		// bytes mapped
		fe->ptr = 0;
		fe->old_ptr = (__u64)(unsigned int)fd;	// the mapped fd
		gadget_submit_buf(ctx, &heap_events, fe, sizeof(*fe));
		return 0;
	}
	if (fd >= 0)			// file-backed: not heap
		return 0;
	if (len == 0)
		return 0;
	if (!mep_proc_wanted())
		return 0;
	struct heap_event *e = gadget_reserve_buf(&heap_events, sizeof(*e));
	if (!e)
		return 0;
	e->timestamp_raw = bpf_ktime_get_boot_ns();
	gadget_process_populate(&e->proc);
	e->heap_op_raw = heap_mmap_anon;
	e->size = len;		// bytes requested
	e->ptr = 0;
	e->old_ptr = 0;
	gadget_submit_buf(ctx, &heap_events, e, sizeof(*e));
	return 0;
}


// ===========================================================================
// ENRICHED KERNEL-SUBSYSTEM FAMILIES — the broad "swiss-army" menu. Each
// capability is a small set of kprobe/tracepoint programs retargeted by the
// SAME enableExact() WASM pattern, with a capability-specific ENRICHED
// datasource (decoded subsystem fields) on top of the generic attach. All are
// READ-ONLY: registers, BTF-typed tracepoint context, and CO-RE struct reads
// only — never a writer helper.
//
// capability = net_trace -> Networking : tcp connect / retransmit / sendmsg
// capability = fs_trace -> Filesystem : vfs_read / vfs_write / vfs_open
// capability = mm_trace -> Memory mgmt: page faults + direct reclaim
// capability = irq_trace -> Drivers/IRQ: softirq entry->exit duration
// capability = block_io -> Block I/O : per-request dev/sector/bytes/latency
// capability = runq_lat -> Scheduler : run-queue (wakeup->on-cpu) latency
// ===========================================================================

// --------------------------------------------------------------- net_trace --
// Networking subsystem. Decodes the connection 4-tuple + result needed to see WHY
// connections are slow or failing:
// - tcp_v4_connect(sk,...) : daddr/dport from struct sock (the target), and
// the kretprobe retval (0 ok; -ECONNREFUSED/-ETIMEDOUT etc. on failure).
// - tcp_retransmit_skb(sk,...) : a retransmit event for sk's 4-tuple (tail
// latency / loss signal).
// - tcp_sendmsg(sk,msg,size) : bytes queued for send (throughput signal).
enum net_op { net_connect, net_retransmit, net_sendmsg, net_udp_send, net_udp_recv };

struct net_event {
	gadget_timestamp timestamp_raw;
	struct gadget_process proc;
	enum net_op net_op_raw;
	__u32 daddr;		// dest IPv4 (network order)
	__u32 saddr;		// src IPv4
	__u16 dport;		// dest port (host order, decoded)
	__u16 sport;		// src port (host order)
	__u64 bytes;		// sendmsg size; 0 otherwise
	__s64 retval;		// connect result (kretprobe); 0 otherwise
	__u32 retrans_out;	// [ENRICH] cumulative retransmits for this conn (icsk_retransmits)
	__u8  tcp_state;	// [ENRICH] TCP state (connect: state at return; retransmit: state at loss)
	gadget_duration connect_latency_ns;	// [ENRICH] tcp_v4_connect entry->return ns (connect op); 0 otherwise
	struct gadget_l4endpoint_t dst_endpoint;	// [k8s_pod_meta] remote peer -> KubeIPResolver (pod/ns/UID)
};

GADGET_TRACER_MAP(net_events, 1024 * 256);
GADGET_TRACER(mep_net, net_events, net_event);

// ============================================================================
// [sockpair_correlate] sockpair_correlate — link a proxy's DOWNSTREAM (accepted) socket to
// the UPSTREAM socket it opens on the SAME worker thread. Envoy/HAProxy service
// both legs from one event-loop tid, so we correlate per-tid: the accepted
// child sock (inet_csk_accept return) is stashed by tid, and the next
// tcp_v4_connect return on that tid emits a sockpair row {down 4-tuple, up
// 4-tuple}. Lives entirely in the net_trace capability (no cross-cap dep).
struct sockpair_event {
	gadget_timestamp timestamp_raw;
	struct gadget_process proc;
	__u32 down_saddr, down_daddr;	// downstream (client<->proxy) 4-tuple
	__u16 down_sport, down_dport;
	__u32 up_saddr, up_daddr;	// upstream (proxy<->backend) 4-tuple
	__u16 up_sport, up_dport;
	__s64 up_retval;	// upstream connect result (0=ok, <0=-errno)
	__u8  down_state, up_state;
	gadget_duration accept_to_connect_ns;	// accept -> upstream-connect gap
};
GADGET_TRACER_MAP(sockpairs, 1024 * 64);
GADGET_TRACER(mep_sockpair, sockpairs, sockpair_event);

struct mep_pending_accept { struct mep_sockid down; __u64 ts; };
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);		// tid
	__type(value, struct mep_pending_accept);
} sockpair_pending SEC(".maps");

// inet_csk_accept returns the newly-accepted child struct sock* (the
// downstream connection). Stash its 4-tuple keyed by the accepting tid.
SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(mep_sockpair_accept, struct sock *child)
{
	if (!child || !mep_proc_wanted())
		return 0;
	struct mep_sockid id;
	mep_decode_sk(child, &id);
	if (id.sk_family != AF_INET)	// v4 correlation
		return 0;
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	struct mep_pending_accept p = { .down = id, .ts = bpf_ktime_get_boot_ns() };
	bpf_map_update_elem(&sockpair_pending, &tid, &p, BPF_ANY);
	return 0;
}

// [k8s_pod_meta] Publish the REMOTE peer of a net event as a
// struct gadget_l4endpoint_t so IG's in-tree KubeIPResolver operator (which
// keys on this exact BTF type) resolves daddr -> podName/namespace/UID +
// service in user space when the gadget runs in Kubernetes. Mesh-critical for
// a connect to a stale/dead endpoint:
// it aligns "connect to 10.x" against the destination POD, not an opaque IP.
//
// Scoped to mep_net ONLY: every net event is definitionally an inet socket op
// (tcp_*/udp_* kprobes), so version is ALWAYS 4. We set version=4 even when
// daddr==0 (unresolved) -> formats as 0.0.0.0 -> KubeIPResolver GetPodByIp
// returns nil -> row emitted unenriched (NO drop). Putting this type on a
// datasource that also carries non-socket rows (mep_sys open/read of a file)
// makes the l4endpoint formatter error "unknown IP version: 0" and DROP the row
// (EmitAndRelease -> processEvent Warnf+continue). v4-only mirrors the
// pre-existing v4-only daddr field (v6 is a separate enhancement).
static __always_inline void mep_fill_net_ep(struct net_event *e)
{
	__builtin_memset(&e->dst_endpoint, 0, sizeof(e->dst_endpoint));
	e->dst_endpoint.addr_raw.v4 = e->daddr;		// network order (matches.v4)
	e->dst_endpoint.port = e->dport;		// already host order
	e->dst_endpoint.proto_raw =
		(e->net_op_raw == net_udp_send || e->net_op_raw == net_udp_recv) ? 17 : 6;
	e->dst_endpoint.version = 4;
}

// ============================================================ per_key_rollup ==
// per_key_rollup. A per-FLOW rollup view over the always-on net
// datasource: instead of scrolling thousands of per-packet rows, IG periodically
// fetches one row PER 4-tuple carrying count, byte-sum, inter-event gap
// min/max/sum (mean = gap_sum/(count-1)), retransmits, inbound-RST count,
// closing-state activity and last TCP state. A ~constant gap => periodic
// keep-alive/ping; a large last-vs-mean gap => idle; bytes_sum==0 with count>1
// => empty keep-alives; closing_evts>0 => write/IO while the socket was tearing
// down (the write-after-peer-FIN shape). Modeled on gadgets/top_tcp's
// per-flow GADGET_MAPITER, EXTENDED with the inter-event gap tracking top_tcp
// lacks. Key is the pure 4-tuple (NOT pid) so the item-12 inbound-RST hook --
// which runs in softirq with no meaningful current task -- can find and bump the
// same flow; the owning pid/comm are recorded as VALUE fields from the first
// event that carried process context.
struct net_rollup_key {
	__u32 daddr;	// remote IPv4 (network order) -- matches net_event.daddr
	__u32 saddr;	// local IPv4 (network order)
	__u16 dport;	// remote port (host order, decoded)
	__u16 sport;	// local port (host order)
};
struct net_rollup_val {
	__u64 count;		// net events observed on this flow
	__u64 first_ts_raw;	// first event (boot ns)
	__u64 last_ts_raw;	// most recent event (boot ns) -- last-gap = now-this
	__u64 gap_min_ns;	// smallest inter-event gap
	__u64 gap_max_ns;	// largest inter-event gap
	__u64 gap_sum_ns;	// sum of gaps; mean = gap_sum_ns/(count-1)
	__u64 bytes_sum;	// total bytes moved (sendmsg/udp size); 0-byte pings visible as count>1,bytes_sum==0
	__u64 retrans_count;	// net_retransmit ops on this flow (loss/blackhole signal)
	__u64 rst_count;	// inbound RSTs on this flow. Populated whenever the
				// mep_tcp_reset hook is co-attached (always under sock_state;
				// and under net_trace via the net_trace keep-set co-attach)
				// so a refused/aborted connect shows rst_count>0 here.
	__u64 closing_evts;	// net events seen while tcp_state was a closing state (CLOSE_WAIT/FIN_WAIT*/LAST_ACK/CLOSING) -- write-after-peer-FIN shape
	__u32 pid;		// owning pid (from first event with proc context)
	__u8  last_state;	// most recent tcp_state on this flow
	gadget_comm comm[TASK_COMM_LEN];	// owning comm
};
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, struct net_rollup_key);
	__type(value, struct net_rollup_val);
} net_rollup_map SEC(".maps");

// GADGET_MAPITER -> IG periodically fetches net_rollup_map into the `net_rollup`
// datasource, flattening key+value struct members into columns.
GADGET_MAPITER(net_rollup, net_rollup_map);

static __always_inline struct net_rollup_val *
net_rollup_slot(struct net_rollup_key *k)
{
	struct net_rollup_val *v = bpf_map_lookup_elem(&net_rollup_map, k);
	if (v)
		return v;
	struct net_rollup_val zero = {};
	bpf_map_update_elem(&net_rollup_map, k, &zero, BPF_NOEXIST);
	return bpf_map_lookup_elem(&net_rollup_map, k);
}

// Fold one net_event into its flow rollup. Called at every net submit site AFTER
// net_decode_sk has populated the 4-tuple. Additive counters use __sync_fetch_
// and_add; the init / min-max / last-write races are benign for a diagnostic
// rollup (top_tcp has the same class of non-atomic init).
static __always_inline void net_rollup_update(struct net_event *e)
{
	struct net_rollup_key k = {};
	k.daddr = e->daddr; k.saddr = e->saddr;
	k.dport = e->dport; k.sport = e->sport;
	if (k.daddr == 0 && k.dport == 0)	// undecoded 4-tuple -> skip junk row
		return;
	struct net_rollup_val *v = net_rollup_slot(&k);
	if (!v)
		return;
	__u64 now = e->timestamp_raw;
	if (v->count == 0) {
		v->first_ts_raw = now;
		v->pid = e->proc.pid;
		__builtin_memcpy(v->comm, e->proc.comm, sizeof(v->comm));
	} else {
		__u64 gap = now - v->last_ts_raw;
		if (v->gap_min_ns == 0 || gap < v->gap_min_ns)
			v->gap_min_ns = gap;
		if (gap > v->gap_max_ns)
			v->gap_max_ns = gap;
		__sync_fetch_and_add(&v->gap_sum_ns, gap);
	}
	v->last_ts_raw = now;
	v->last_state = e->tcp_state;
	__sync_fetch_and_add(&v->count, 1);
	if (e->bytes)
		__sync_fetch_and_add(&v->bytes_sum, e->bytes);
	if (e->net_op_raw == net_retransmit)
		__sync_fetch_and_add(&v->retrans_count, 1);
	// closing-state activity: CLOSE_WAIT(8) FIN_WAIT1(4) FIN_WAIT2(5)
	// LAST_ACK(9) CLOSING(11) -- a write/IO here is the write-after-peer-FIN /
	// activity-during-teardown signal.
	__u8 st = e->tcp_state;
	if (st == 8 || st == 4 || st == 5 || st == 9 || st == 11)
		__sync_fetch_and_add(&v->closing_evts, 1);
}

// Bump the inbound-RST counter for a flow. Called from the item-12 tcp_reset
// hook (inbound RST on an EXISTING socket, so the 4-tuple orientation matches a
// flow the net path already created). softirq-safe: no current-task access.
static __always_inline void net_rollup_rst(__u32 daddr, __u32 saddr,
					   __u16 dport, __u16 sport)
{
	struct net_rollup_key k = {};
	k.daddr = daddr; k.saddr = saddr; k.dport = dport; k.sport = sport;
	if (k.daddr == 0 && k.dport == 0)
		return;
	// LOOKUP-ONLY (no create-on-miss): only bump the RST counter on a flow the
	// net family is ALREADY tracking. This hook also fires under sock_state
	// (where the net programs are not attached and no rollup slot exists); it
	// must NOT spawn an orphan rollup row there (rst_count=1, count=0, no
	// 4-tuple gap data). Under sock_state the affirmative RST signal is carried
	// by the dedicated ss_reset_rx datasource instead.
	struct net_rollup_val *v = bpf_map_lookup_elem(&net_rollup_map, &k);
	if (!v)
		return;
	__sync_fetch_and_add(&v->rst_count, 1);
	v->last_ts_raw = bpf_ktime_get_boot_ns();
}

// carry sk pointer from tcp_v4_connect entry -> return so we can decode the
// 4-tuple at return time (when the connection fields are populated) AND attach
// the retval.
// value carries the connecting sock* AND the entry timestamp so the return
// probe can compute connect latency (entry -> tcp_v4_connect return).
struct net_connect_ctx { __u64 skp; __u64 ts; };
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, __u32);	// tid
	__type(value, struct net_connect_ctx);
} net_connect_sk SEC(".maps");

static __always_inline void net_decode_sk(struct net_event *e, struct sock *sk)
{
	// read each field individually via CO-RE (no struct-by-value stack copy).
	e->daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
	e->saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
	__u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
	e->dport = bpf_ntohs(dport);
	e->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
	// [per_conn_identity] socket state on EVERY net event (not just connect/
	// retransmit): sendmsg/udp rows now prove WHICH tcp_state the socket was in
	// when the write happened — e.g. a tcp_sendmsg on a CLOSE_WAIT(8) socket is
	// the affirmative write-after-peer-FIN signal (write-after-peer-FIN), and an
	// ESTABLISHED(1) vs SYN_SENT(2) sendmsg distinguishes live vs racing conn.
	e->tcp_state = BPF_CORE_READ(sk, __sk_common.skc_state);
}

static __always_inline struct net_event *net_new(enum net_op op)
{
	if (!mep_proc_wanted())
		return 0;
	struct net_event *e = gadget_reserve_buf(&net_events, sizeof(*e));
	if (!e) return 0;
	e->timestamp_raw = bpf_ktime_get_boot_ns();
	gadget_process_populate(&e->proc);
	e->net_op_raw = op;
	e->daddr = e->saddr = 0; e->dport = e->sport = 0; e->bytes = 0; e->retval = 0;
	e->retrans_out = 0; e->tcp_state = 0; e->connect_latency_ns = 0;
	return e;
}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(mep_net_connect, struct sock *sk)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	struct net_connect_ctx c = { .skp = (__u64)sk, .ts = bpf_ktime_get_boot_ns() };
	bpf_map_update_elem(&net_connect_sk, &tid, &c, BPF_ANY);
	return 0;
}
SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(mep_net_connect_ret, int ret)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	struct net_connect_ctx *c = bpf_map_lookup_elem(&net_connect_sk, &tid);
	if (!c) return 0;
	struct sock *sk = (struct sock *)c->skp;
	__u64 t0 = c->ts;
	bpf_map_delete_elem(&net_connect_sk, &tid);
	struct net_event *e = net_new(net_connect);
	if (!e) return 0;
	net_decode_sk(e, sk);
	e->retval = ret;
	// [ENRICH] connect-time tcp_state + entry->return latency so "slow outbound
	// connect" is directly measurable as connect-to-established time.
	e->tcp_state = BPF_CORE_READ(sk, __sk_common.skc_state);
	e->connect_latency_ns = bpf_ktime_get_boot_ns() - t0;
	net_rollup_update(e);
	mep_fill_net_ep(e);
	gadget_submit_buf(ctx, &net_events, e, sizeof(*e));
	// [sockpair_correlate] if this worker recently accepted a downstream conn, pair it with
	// this upstream connect (same tid = same proxy worker servicing both legs).
	{
		struct mep_pending_accept *pa = bpf_map_lookup_elem(&sockpair_pending, &tid);
		if (pa) {
			struct sockpair_event *sp = gadget_reserve_buf(&sockpairs, sizeof(*sp));
			if (sp) {
				sp->timestamp_raw = bpf_ktime_get_boot_ns();
				gadget_process_populate(&sp->proc);
				sp->down_saddr = pa->down.saddr; sp->down_daddr = pa->down.daddr;
				sp->down_sport = pa->down.sport; sp->down_dport = pa->down.dport;
				sp->down_state = pa->down.sk_state;
				struct mep_sockid uid; mep_decode_sk(sk, &uid);
				sp->up_saddr = uid.saddr; sp->up_daddr = uid.daddr;
				sp->up_sport = uid.sport; sp->up_dport = uid.dport;
				sp->up_state = uid.sk_state; sp->up_retval = ret;
				sp->accept_to_connect_ns = (sp->timestamp_raw > pa->ts) ?
					(sp->timestamp_raw - pa->ts) : 0;
				gadget_submit_buf(ctx, &sockpairs, sp, sizeof(*sp));
			}
			bpf_map_delete_elem(&sockpair_pending, &tid);
		}
	}
	return 0;
}

SEC("kprobe/tcp_retransmit_skb")
int BPF_KPROBE(mep_net_retransmit, struct sock *sk)
{
	struct net_event *e = net_new(net_retransmit);
	if (!e) return 0;
	net_decode_sk(e, sk);
	// [ENRICH] cumulative retransmit count distinguishes one-off loss from a
	// blackhole storm; TCP state separates connect-time (SYN_SENT) from mid-stream.
	struct inet_connection_sock *icsk = (struct inet_connection_sock *)sk;
	e->retrans_out = BPF_CORE_READ(icsk, icsk_retransmits);
	e->tcp_state   = BPF_CORE_READ(sk, __sk_common.skc_state);
	net_rollup_update(e);
	mep_fill_net_ep(e);
	gadget_submit_buf(ctx, &net_events, e, sizeof(*e));
	return 0;
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(mep_net_sendmsg, struct sock *sk, struct msghdr *msg, size_t size)
{
	struct net_event *e = net_new(net_sendmsg);
	if (!e) return 0;
	net_decode_sk(e, sk);
	e->bytes = size;
	net_rollup_update(e);
	mep_fill_net_ep(e);
	gadget_submit_buf(ctx, &net_events, e, sizeof(*e));
	return 0;
}

// [ENRICH] UDP coverage. TCP-only net_trace makes UDP-based name resolution
// (DNS over :53) and other datagram traffic invisible, so a "slow / failing
// name lookup" symptom shows no net evidence at all. udp_sendmsg/udp_recvmsg
// decode the connected-socket 4-tuple (glibc connect()s the UDP socket for a
// stub-resolver query, so skc_daddr/skc_dport are populated) and the byte
// count, giving the MCP client direct visibility of the :53 request/response pair.
SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(mep_net_udp_send, struct sock *sk, struct msghdr *msg, size_t size)
{
	struct net_event *e = net_new(net_udp_send);
	if (!e) return 0;
	net_decode_sk(e, sk);
	e->bytes = size;
	net_rollup_update(e);
	mep_fill_net_ep(e);
	gadget_submit_buf(ctx, &net_events, e, sizeof(*e));
	return 0;
}

SEC("kprobe/udp_recvmsg")
int BPF_KPROBE(mep_net_udp_recv, struct sock *sk, struct msghdr *msg, size_t size)
{
	struct net_event *e = net_new(net_udp_recv);
	if (!e) return 0;
	net_decode_sk(e, sk);
	e->bytes = size;
	net_rollup_update(e);
	mep_fill_net_ep(e);
	gadget_submit_buf(ctx, &net_events, e, sizeof(*e));
	return 0;
}

// ============================================================= sock_state ==
// capability: sock_state — TCP connection-lifecycle visibility.
//
// sock_state — sock/inet_sock_set_state tracepoint. EVERY TCP state transition for
// the 4-tuple with old->new state. Directly answers "did this connection ever
// reach ESTABLISHED or die in SYN_SENT?" and "when did the peer half-close
// (ESTABLISHED->CLOSE_WAIT)?" without hand-diffing syscall traces.
enum sockstate_op { ss_transition, ss_reset_rx, ss_reset_tx };

struct sockstate_event {
	gadget_timestamp timestamp_raw;
	struct gadget_process proc;
	enum sockstate_op ss_op_raw;
	__u32 saddr;		// local IPv4 (network order)
	__u32 daddr;		// remote IPv4 (network order)
	__u16 sport;		// local port (host order)
	__u16 dport;		// remote port (host order)
	__s32 oldstate;		// [transition] previous TCP state
	__s32 newstate;		// [transition] new TCP state; [reset] state at reset
	__u16 family;		// 2=AF_INET, 10=AF_INET6
	__u8  reset_dir;	// [sock_state] 0=n/a(transition), 1=inbound RST recv, 2=outbound RST sent
	__u8  sk_null;		// [sock_state] 1 if the (send_)reset had sk==NULL (no socket)
};

GADGET_TRACER_MAP(sockstate_events, 1024 * 256);
GADGET_TRACER(mep_sockstate, sockstate_events, sockstate_event);

static __always_inline struct sockstate_event *sockstate_new(enum sockstate_op op)
{
	struct sockstate_event *e = gadget_reserve_buf(&sockstate_events, sizeof(*e));
	if (!e) return 0;
	e->timestamp_raw = bpf_ktime_get_boot_ns();
	gadget_process_populate(&e->proc);
	e->ss_op_raw = op;
	e->saddr = e->daddr = 0; e->sport = e->dport = 0;
	e->oldstate = e->newstate = 0; e->family = 0;
	e->reset_dir = 0; e->sk_null = 0;
	return e;
}

// sock_state: system-wide TCP state-transition tracer. Fires in both process and
// softirq context (passive SYN_RECV->ESTABLISHED etc.), so it is NOT proc-gated
// — the MCP client scopes by 4-tuple. TCP-only (protocol==IPPROTO_TCP==6).
SEC("tracepoint/sock/inet_sock_set_state")
int mep_sock_set_state(struct trace_event_raw_inet_sock_set_state *ctx)
{
	if (ctx->protocol != 6)	// IPPROTO_TCP
		return 0;
	struct sockstate_event *e = sockstate_new(ss_transition);
	if (!e) return 0;
	e->oldstate = ctx->oldstate;
	e->newstate = ctx->newstate;
	e->sport = ctx->sport;	// tracepoint stores host-order sport/dport
	e->dport = ctx->dport;
	e->family = ctx->family;
	// saddr/daddr are raw __be32 stored in u8[4] arrays; copy the 4 bytes.
	__builtin_memcpy(&e->saddr, ctx->saddr, 4);
	__builtin_memcpy(&e->daddr, ctx->daddr, 4);
	gadget_submit_buf(ctx, &sockstate_events, e, sizeof(*e));
	return 0;
}

// Inbound RST: inbound RST RECEIVED on an existing socket (reset_dir=1).
SEC("kprobe/tcp_reset")
int BPF_KPROBE(mep_tcp_reset, struct sock *sk)
{
	struct sockstate_event *e = sockstate_new(ss_reset_rx);
	if (!e) return 0;
	e->reset_dir = 1;
	if (sk) {
		e->daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
		e->saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
		__u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
		e->dport = bpf_ntohs(dport);
		e->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
		e->newstate = BPF_CORE_READ(sk, __sk_common.skc_state);
		e->family = BPF_CORE_READ(sk, __sk_common.skc_family);
	} else {
		e->sk_null = 1;
	}
	// [per_key_rollup] unify: this inbound RST also increments the flow's rollup rst_count
	// (same 4-tuple orientation as the net path). The sk==NULL outbound
	// send_reset smoking-gun stays in the dedicated ss_reset_tx row (reversed
	// skb orientation would not unify by flow key).
	net_rollup_rst(e->daddr, e->saddr, e->dport, e->sport);
	gadget_submit_buf(ctx, &sockstate_events, e, sizeof(*e));
	return 0;
}

// Outbound RST: outbound RST SENT (reset_dir=2). sk==NULL => no matching socket
// (stale/torn-down endpoint) — the stale-endpoint smoking gun. When sk==NULL the
// 4-tuple is recovered from the offending inbound skb so the row still names
// which remote endpoint got the RST.
SEC("kprobe/tcp_v4_send_reset")
int BPF_KPROBE(mep_tcp_send_reset, const struct sock *sk, struct sk_buff *skb)
{
	struct sockstate_event *e = sockstate_new(ss_reset_tx);
	if (!e) return 0;
	e->reset_dir = 2;
	e->family = 2;	// AF_INET (v4 path)
	if (sk) {
		e->daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
		e->saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
		__u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
		e->dport = bpf_ntohs(dport);
		e->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
		e->newstate = BPF_CORE_READ(sk, __sk_common.skc_state);
	} else {
		e->sk_null = 1;
		// Parse the inbound packet we are RSTing so the row names its target.
		void *head = (void *)BPF_CORE_READ(skb, head);
		__u16 net_off = BPF_CORE_READ(skb, network_header);
		__u16 tr_off  = BPF_CORE_READ(skb, transport_header);
		struct iphdr iph = {};
		struct tcphdr th = {};
		bpf_probe_read_kernel(&iph, sizeof(iph), (char *)head + net_off);
		bpf_probe_read_kernel(&th,  sizeof(th),  (char *)head + tr_off);
		// Inbound packet: iph.saddr is the remote peer that got the RST.
		e->daddr = iph.saddr;	// remote (sender of the offending packet)
		e->saddr = iph.daddr;	// us
		e->dport = bpf_ntohs(th.source);	// remote port
		e->sport = bpf_ntohs(th.dest);		// our (nonexistent) local port
	}
	gadget_submit_buf(ctx, &sockstate_events, e, sizeof(*e));
	return 0;
}

// ===========================================================================
// [errno_decode / causal death linkage] sched:sched_process_exit
// When a process that trace_syscall was watching EXITS, pair its exit code
// with the LAST failed socket syscall it made (last_sockfail). The emitted
// mep_death row answers the dependency-death question directly: "pid 1234 exited
// (code=1) 3.2ms after connect(10.0.0.5:8080) failed ECONNREFUSED" -- causal
// dependency-death, not a guess. Only fires for the group leader (pid==tgid)
// and only when a failure was recorded, so it inherits trace_syscall's pid
// scope and stays silent for healthy processes.
// ===========================================================================
struct death_event {
	gadget_timestamp timestamp_raw;
	struct gadget_process proc;
	__s32 exit_code;		// task->exit_code (>>8 = status, &0x7f = signal)
	gadget_errno last_err_raw;	// errno of the last failed socket syscall
	enum mep_errclass last_err_class_raw;
	__u32 last_nr;			// which syscall failed (42=connect)
	gadget_duration gap_ns;		// exit_ts - fail_ts (how soon after the failure)
	__u32 saddr, daddr;		// intended peer of the failed syscall
	__u16 sport, dport;
	__u8  sk_family;
};
GADGET_TRACER_MAP(death_events, 64 * 1024);
GADGET_TRACER(mep_death, death_events, death_event);

SEC("tracepoint/sched/sched_process_exit")
int mep_death_probe(void *ctx)
{
	__u64 pt = bpf_get_current_pid_tgid();
	__u32 tgid = pt >> 32;
	__u32 pid  = (__u32)pt;
	if (pid != tgid)		// only the group leader's exit == process death
		return 0;
	struct mep_sockfail *f = bpf_map_lookup_elem(&last_sockfail, &tgid);
	if (!f)				// process made no failed socket call -- silent
		return 0;

	struct death_event *e = gadget_reserve_buf(&death_events, sizeof(*e));
	if (!e) { bpf_map_delete_elem(&last_sockfail, &tgid); return 0; }
	__u64 now = bpf_ktime_get_boot_ns();
	e->timestamp_raw = now;
	gadget_process_populate(&e->proc);
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	e->exit_code = BPF_CORE_READ(task, exit_code);
	e->last_err_raw = f->err;
	e->last_err_class_raw = (enum mep_errclass)f->err_class;
	e->last_nr = f->nr;
	e->gap_ns = (now > f->ts) ? (now - f->ts) : 0;
	e->saddr = f->saddr; e->daddr = f->daddr;
	e->sport = f->sport; e->dport = f->dport;
	e->sk_family = f->sk_family;
	gadget_submit_buf(ctx, &death_events, e, sizeof(*e));
	bpf_map_delete_elem(&last_sockfail, &tgid);
	return 0;
}

// ---------------------------------------------------------------- fs_trace --
// Filesystem subsystem. Per-call VFS activity with the byte count + result, exposing a
// hot read/write path or a failing open:
// - vfs_read(file,buf,count,pos) : requested count (entry) + bytes read (ret)
// - vfs_write(file,buf,count,pos) : requested count (entry) + bytes written (ret)
// - vfs_open(path,file) : open events (ret 0 ok / -errno)
enum fs_op { fs_read, fs_write, fs_open, fs_filp_open, fs_io_submit, fs_io_uring_enter, fs_close };

struct fs_event {
	gadget_timestamp timestamp_raw;
	struct gadget_process proc;
	enum fs_op fs_op_raw;
	__u64 count;		// requested bytes (read/write)
	__s64 retval;		// bytes transferred OR open result (0 ok / -errno)
	char fname[256];	// failing-open path (fs_filp_open); empty for rw/open
	// [per_conn_identity fs] populated when the fd is actually a socket — an
	// fs read/write/close on a TCP/UDP socket. Makes "write on a CLOSE_WAIT(8)
	// socket" (write-after-peer-FIN) visible. sk_family=0 for regular files.
	__u32 saddr, daddr;
	__u16 sport, dport;
	__u8  sk_state, sk_family;
};

GADGET_TRACER_MAP(fs_events, 1024 * 256);
GADGET_TRACER(mep_fs, fs_events, fs_event);

struct fs_pending { enum fs_op op; __u64 count; char name[128]; struct mep_sockid sid; };
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, __u32);
	__type(value, struct fs_pending);
} fs_pending_map SEC(".maps");

// ---- fs_trace server-side filters -----------------------
// The unfiltered fs_trace stream is dominated by system-wide vfs_read/vfs_write
// (>500k events/window); a rare failing open (do_filp_open -> -ENOENT) is ~0.08%
// and gets truncated out of the MCP result window before the MCP client ever sees it.
// Two in-kernel reductions let the MCP client (or the gadget) cut that noise AT THE
// SOURCE so the diagnostic rows survive truncation:
// 1. filter_fs_op : keep only ONE op class, or only faults (retval<0). The
// client selects it with the `fs_op` MCP param; default 0 == keep all.
// 2. fs_is_self() : ALWAYS drop the tracer's own ig / ig-mcp-server I/O so the
// gadget never reports its bookkeeping reads/writes as application activity.
#define FS_FILTER_ALL   0
#define FS_FILTER_READ  1
#define FS_FILTER_WRITE 2
#define FS_FILTER_OPEN  3
#define FS_FILTER_FILP  4
#define FS_FILTER_FAULT 5
#define FS_FILTER_CLOSE 6
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} filter_fs_op SEC(".maps");

static __always_inline bool fs_is_self(void)
{
	char comm[16];
	bpf_get_current_comm(&comm, sizeof(comm));
	// "ig" (exact) or "ig-..." (e.g. ig-mcp-server): the tracer's own threads.
	return comm[0] == 'i' && comm[1] == 'g' && (comm[2] == '\0' || comm[2] == '-');
}

static __always_inline bool fs_emit_wanted(enum fs_op op, __s64 ret)
{
	if (fs_is_self())
		return false;
	__u32 k = 0;
	__u64 *f = bpf_map_lookup_elem(&filter_fs_op, &k);
	if (!f || *f == FS_FILTER_ALL)
		return true;
	if (*f == FS_FILTER_FAULT) {
		// A "fault" is a GENUINE diagnostic error worth surfacing (ENOENT,
		// EACCES, EIO, ENOSPC,...). Benign flow-control returns are NOT faults
		// and, on a busy host, vfs_read on non-blocking sockets emits a CONSTANT
		// -EAGAIN flood that drowns the rare diagnostic rows under MCP response
		// truncation (validated: fs_op=fault carried 496 EAGAIN
		// reads vs 0 surfaced openat->ENOENT). Drop the would-block / retry /
		// interrupt class so the real fault (e.g. missing-config ENOENT) survives.
		if (ret >= 0)
			return false;          // success path is never a fault
		__s64 e = -ret;            // positive errno
		if (e == 11  /* EAGAIN == EWOULDBLOCK */ ||
		    e == 4   /* EINTR */ ||
		    e == 115 /* EINPROGRESS */ ||
		    e == 512 /* ERESTARTSYS */ ||
		    e == 513 /* ERESTARTNOINTR */ ||
		    e == 514 /* ERESTARTNOHAND */)
			return false;          // benign flow-control, not a diagnostic fault
		return true;               // genuine fault -> surface it
	}
	if (*f == FS_FILTER_READ)
		return op == fs_read;
	if (*f == FS_FILTER_WRITE)
		return op == fs_write;
	if (*f == FS_FILTER_OPEN)
		return op == fs_open;
	if (*f == FS_FILTER_FILP)
		return op == fs_filp_open;
	if (*f == FS_FILTER_CLOSE)
		return op == fs_close;
	return true;
}

static __always_inline int fs_rw_enter_named(enum fs_op op, __u64 count,
					    struct dentry *de, struct sock *sk)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	struct fs_pending p = { .op = op, .count = count };
	// [per_conn_identity fs] stash socket identity if this fd is a socket.
	mep_decode_sk(sk, &p.sid);
	// capture the dentry leaf name (e.g. "app.conf") so fs_trace rows
	// answer WHICH file, not just how much I/O. Bounded kernel-str read; leaf
	// only (not full path) to stay clear of the bpf_d_path hook allowlist.
	if (de) {
		const char *nm = (const char *)BPF_CORE_READ(de, d_name.name);
		if (nm)
			bpf_probe_read_kernel_str(p.name, sizeof(p.name), nm);
	}
	bpf_map_update_elem(&fs_pending_map, &tid, &p, BPF_ANY);
	return 0;
}
static __always_inline int fs_rw_enter(enum fs_op op, __u64 count)
{
	return fs_rw_enter_named(op, count, NULL, (struct sock *)0);
}
static __always_inline int fs_rw_exit(void *ctx, long ret)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	struct fs_pending *p = bpf_map_lookup_elem(&fs_pending_map, &tid);
	if (!p) return 0;
	enum fs_op op = p->op; __u64 count = p->count;
	struct mep_sockid sid = p->sid;
	bpf_map_delete_elem(&fs_pending_map, &tid);
	if (!mep_proc_wanted())
		return 0;
	if (!fs_emit_wanted(op, (__s64)ret))
		return 0;
	struct fs_event *e = gadget_reserve_buf(&fs_events, sizeof(*e));
	if (!e) return 0;
	e->timestamp_raw = bpf_ktime_get_boot_ns();
	gadget_process_populate(&e->proc);
	e->fs_op_raw = op; e->count = count; e->retval = (__s64)ret;
	// surface the leaf filename captured at enter (empty if unknown).
	__builtin_memcpy(e->fname, p->name, sizeof(e->fname) < sizeof(p->name) ? sizeof(e->fname) : sizeof(p->name));
	e->fname[sizeof(e->fname) - 1] = '\0';
	e->saddr = sid.saddr; e->daddr = sid.daddr; e->sport = sid.sport;
	e->dport = sid.dport; e->sk_state = sid.sk_state; e->sk_family = sid.sk_family;
	gadget_submit_buf(ctx, &fs_events, e, sizeof(*e));
	return 0;
}

// ssize_t vfs_read(struct file *, char __user *, size_t count, loff_t *pos)
SEC("kprobe/vfs_read")
int BPF_KPROBE(mep_fs_read, struct file *f, void *buf, size_t count) { return fs_rw_enter_named(fs_read, count, BPF_CORE_READ(f, f_path.dentry), mep_sock_from_file(f)); }
SEC("kretprobe/vfs_read")
int BPF_KRETPROBE(mep_fs_read_ret, long ret) { return fs_rw_exit(ctx, ret); }

SEC("kprobe/vfs_write")
int BPF_KPROBE(mep_fs_write, struct file *f, void *buf, size_t count) { return fs_rw_enter_named(fs_write, count, BPF_CORE_READ(f, f_path.dentry), mep_sock_from_file(f)); }
SEC("kretprobe/vfs_write")
int BPF_KRETPROBE(mep_fs_write_ret, long ret) { return fs_rw_exit(ctx, ret); }

SEC("kprobe/vfs_open")
int BPF_KPROBE(mep_fs_open, struct path *path) { return fs_rw_enter_named(fs_open, 0, BPF_CORE_READ(path, dentry), (struct sock *)0); }
SEC("kretprobe/vfs_open")
int BPF_KRETPROBE(mep_fs_open_ret, long ret) { return fs_rw_exit(ctx, ret); }

// int filp_close(struct file *filp, fl_owner_t id) — the VFS close that backs
// close(2) (and close-on-exec + exit-time fd teardown). It is the RELEASE side
// that balances vfs_open above: with both an MCP client computes a per-PID
// open-minus-close balance, the fd-leak signal (opens that accumulate
// with no matching close). Single-shot emit — close has no diagnostic return
// worth pairing for the balance, so no enter/ret stash is needed.
SEC("kprobe/filp_close")
int BPF_KPROBE(mep_fs_close, struct file *f)
{
	if (!mep_proc_wanted())
		return 0;
	if (!fs_emit_wanted(fs_close, 0))
		return 0;
	struct fs_event *e = gadget_reserve_buf(&fs_events, sizeof(*e));
	if (!e) return 0;
	e->timestamp_raw = bpf_ktime_get_boot_ns();
	gadget_process_populate(&e->proc);
	e->fs_op_raw = fs_close; e->count = 0; e->retval = 0;
	e->fname[0] = '\0';
	struct dentry *de = BPF_CORE_READ(f, f_path.dentry);
	if (de) {
		const char *nm = (const char *)BPF_CORE_READ(de, d_name.name);
		if (nm)
			bpf_probe_read_kernel_str(e->fname, sizeof(e->fname), nm);
	}
	// [per_conn_identity fs] a close on a socket fd names the 4-tuple+state at
	// teardown (e.g. close of a socket still in ESTABLISHED = abortive close).
	{ struct mep_sockid _id; mep_decode_sk(mep_sock_from_file(f), &_id);
	  e->saddr = _id.saddr; e->daddr = _id.daddr; e->sport = _id.sport;
	  e->dport = _id.dport; e->sk_state = _id.sk_state; e->sk_family = _id.sk_family; }
	gadget_submit_buf(ctx, &fs_events, e, sizeof(*e));
	return 0;
}

// do_filp_open(int dfd, struct filename *pathname, const struct open_flags *op)
// returns struct file* or ERR_PTR(-errno). It runs BEFORE vfs_open and FAILS at
// path resolution for a missing path, so it is the ONLY fs-layer hook that sees
// openat()->ENOENT (vfs_open is never reached). Entry stashes the requested path;
// the return emits ONLY failing opens (IS_ERR) since successful opens are already
// covered by vfs_open above. Result: fs_trace surfaces the failing path + errno.
struct fs_filp_pend { __u64 name_ptr; };
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, __u32);
	__type(value, struct fs_filp_pend);
} fs_filp_pending SEC(".maps");

SEC("kprobe/do_filp_open")
int BPF_KPROBE(mep_fs_filp_open, int dfd, struct filename *pathname)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	struct fs_filp_pend p = {};
	p.name_ptr = (__u64)(unsigned long)BPF_CORE_READ(pathname, name);
	bpf_map_update_elem(&fs_filp_pending, &tid, &p, BPF_ANY);
	return 0;
}
SEC("kretprobe/do_filp_open")
int BPF_KRETPROBE(mep_fs_filp_open_ret, long ret)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	struct fs_filp_pend *p = bpf_map_lookup_elem(&fs_filp_pending, &tid);
	if (!p) return 0;
	__u64 name_ptr = p->name_ptr;
	bpf_map_delete_elem(&fs_filp_pending, &tid);
	if (!mep_proc_wanted())
		return 0;
	// emit ONLY failing opens: ERR_PTR range [-4095, -1]
	if (ret >= 0 || ret < -4095)
		return 0;
	if (!fs_emit_wanted(fs_filp_open, (__s64)ret))
		return 0;
	struct fs_event *e = gadget_reserve_buf(&fs_events, sizeof(*e));
	if (!e) return 0;
	e->timestamp_raw = bpf_ktime_get_boot_ns();
	gadget_process_populate(&e->proc);
	e->fs_op_raw = fs_filp_open;
	e->count = 0;
	e->retval = (__s64)ret;
	e->fname[0] = '\0';
	if (name_ptr)
		bpf_probe_read_kernel_str(e->fname, sizeof(e->fname), (const char *)name_ptr);
	gadget_submit_buf(ctx, &fs_events, e, sizeof(*e));
	return 0;
}

// ---------------------------------------------------------------- mm_trace --
// Memory-management subsystem. Two complementary signals for observing memory pressure:
// - handle_mm_fault(...) : page-fault RATE (minor/major fault pressure)
// - try_to_free_pages(...) : DIRECT RECLAIM entry+duration (the smoking gun
// of memory pressure — the kernel is synchronously reclaiming to satisfy an
// allocation, stalling the faulting task).
enum mm_op { mm_fault, mm_reclaim };

struct mm_event {
	gadget_timestamp timestamp_raw;
	struct gadget_process proc;
	enum mm_op mm_op_raw;
	gadget_duration duration_ns;	// reclaim wall-clock (try_to_free_pages); 0 for fault
	__s64 retval;		// reclaim: nr pages reclaimed; fault: 0
};

GADGET_TRACER_MAP(mm_events, 1024 * 256);
GADGET_TRACER(mep_mm, mm_events, mm_event);

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, __u32);
	__type(value, __u64);	// reclaim entry ts
} mm_reclaim_enter SEC(".maps");

SEC("kprobe/handle_mm_fault")
int BPF_KPROBE(mep_mm_fault)
{
	if (!mep_proc_wanted())
		return 0;
	struct mm_event *e = gadget_reserve_buf(&mm_events, sizeof(*e));
	if (!e) return 0;
	e->timestamp_raw = bpf_ktime_get_boot_ns();
	gadget_process_populate(&e->proc);
	e->mm_op_raw = mm_fault; e->duration_ns = 0; e->retval = 0;
	gadget_submit_buf(ctx, &mm_events, e, sizeof(*e));
	return 0;
}

SEC("kprobe/try_to_free_pages")
int BPF_KPROBE(mep_mm_reclaim)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	__u64 ts = bpf_ktime_get_boot_ns();
	bpf_map_update_elem(&mm_reclaim_enter, &tid, &ts, BPF_ANY);
	return 0;
}
SEC("kretprobe/try_to_free_pages")
int BPF_KRETPROBE(mep_mm_reclaim_ret, long ret)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	__u64 *tsp = bpf_map_lookup_elem(&mm_reclaim_enter, &tid);
	if (!tsp) return 0;
	__u64 dur = bpf_ktime_get_boot_ns() - *tsp;
	bpf_map_delete_elem(&mm_reclaim_enter, &tid);
	if (!mep_proc_wanted())
		return 0;
	struct mm_event *e = gadget_reserve_buf(&mm_events, sizeof(*e));
	if (!e) return 0;
	e->timestamp_raw = bpf_ktime_get_boot_ns();
	gadget_process_populate(&e->proc);
	e->mm_op_raw = mm_reclaim; e->duration_ns = dur; e->retval = (__s64)ret;
	gadget_submit_buf(ctx, &mm_events, e, sizeof(*e));
	return 0;
}

// --- memcg direct reclaim (Directive B) -------------------------------------
// try_to_free_mem_cgroup_pages() is the per-cgroup direct-reclaim entry: it fires
// when a process hits its memory-cgroup limit and the kernel must SYNCHRONOUSLY
// reclaim to satisfy the allocation. This is the smoking gun of *scoped* memory
// pressure (the common production case: a container/pod hitting memory.max), which
// global try_to_free_pages() misses on a big-RAM host. Same mm_reclaim event/field
// shape so the consumer sees one coherent "direct reclaim" signal regardless of path.
SEC("kprobe/try_to_free_mem_cgroup_pages")
int BPF_KPROBE(mep_mm_memcg_reclaim)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	__u64 ts = bpf_ktime_get_boot_ns();
	bpf_map_update_elem(&mm_reclaim_enter, &tid, &ts, BPF_ANY);
	return 0;
}
SEC("kretprobe/try_to_free_mem_cgroup_pages")
int BPF_KRETPROBE(mep_mm_memcg_reclaim_ret, long ret)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	__u64 *tsp = bpf_map_lookup_elem(&mm_reclaim_enter, &tid);
	if (!tsp) return 0;
	__u64 dur = bpf_ktime_get_boot_ns() - *tsp;
	bpf_map_delete_elem(&mm_reclaim_enter, &tid);
	if (!mep_proc_wanted())
		return 0;
	struct mm_event *e = gadget_reserve_buf(&mm_events, sizeof(*e));
	if (!e) return 0;
	e->timestamp_raw = bpf_ktime_get_boot_ns();
	gadget_process_populate(&e->proc);
	e->mm_op_raw = mm_reclaim; e->duration_ns = dur; e->retval = (__s64)ret;
	gadget_submit_buf(ctx, &mm_events, e, sizeof(*e));
	return 0;
}

// --------------------------------------------------------------- irq_trace --
// Drivers/IRQ subsystem. Softirq servicing time per vector — a long softirq
// (e.g. NET_RX under a packet storm, or BLOCK under I/O completion pressure)
// steals CPU from tasks. tracepoint entry->exit delta per (cpu) gives the
// service duration; vec identifies the softirq class.
struct irq_event {
	gadget_timestamp timestamp_raw;
	struct gadget_process proc;
	__u32 vec;		// softirq vector (0=HI,1=TIMER,2=NET_TX,3=NET_RX,4=BLOCK,...)
	gadget_duration duration_ns;	// entry->exit service time
};

GADGET_TRACER_MAP(irq_events, 1024 * 256);
GADGET_TRACER(mep_irq, irq_events, irq_event);

// per-cpu scratch: softirq runs with preemption disabled so entry/exit are on
// the same CPU and cannot nest for the same vec; key by cpu.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);	// entry ts
} irq_enter_ts SEC(".maps");

SEC("tracepoint/irq/softirq_entry")
int mep_irq_entry(struct trace_event_raw_softirq *ctx)
{
	__u32 z = 0;
	__u64 ts = bpf_ktime_get_boot_ns();
	bpf_map_update_elem(&irq_enter_ts, &z, &ts, BPF_ANY);
	return 0;
}
SEC("tracepoint/irq/softirq_exit")
int mep_irq_exit(struct trace_event_raw_softirq *ctx)
{
	__u32 z = 0;
	__u64 *tsp = bpf_map_lookup_elem(&irq_enter_ts, &z);
	if (!tsp || *tsp == 0) return 0;
	__u64 dur = bpf_ktime_get_boot_ns() - *tsp;
	struct irq_event *e = gadget_reserve_buf(&irq_events, sizeof(*e));
	if (!e) return 0;
	e->timestamp_raw = bpf_ktime_get_boot_ns();
	gadget_process_populate(&e->proc);
	e->vec = ctx->vec;
	e->duration_ns = dur;
	gadget_submit_buf(ctx, &irq_events, e, sizeof(*e));
	return 0;
}

// async I/O submission. Neither io_submit(2) nor io_uring_enter(2) has a
// sys_enter tracepoint, so we attach via ksyscall (libbpf resolves the arch
// wrapper). These surface async-I/O submission that never appears as a
// read()/write() syscall: an MCP client seeing high throughput but few rw syscalls
// finds the work here. count = number of ops submitted in this call.
SEC("ksyscall/io_uring_enter")
int BPF_KSYSCALL(mep_fs_io_uring_enter, unsigned int fd, unsigned int to_submit, unsigned int min_complete, unsigned int flags)
{
	if (!mep_proc_wanted())
		return 0;
	struct fs_event *e = gadget_reserve_buf(&fs_events, sizeof(*e));
	if (!e)
		return 0;
	e->timestamp_raw = bpf_ktime_get_boot_ns();
	gadget_process_populate(&e->proc);
	e->fs_op_raw = fs_io_uring_enter;
	e->count = (__u64)to_submit;	// SQEs submitted this call
	e->retval = 0;
	e->fname[0] = '\0';
	gadget_submit_buf(ctx, &fs_events, e, sizeof(*e));
	return 0;
}

SEC("ksyscall/io_submit")
int BPF_KSYSCALL(mep_fs_io_submit, long aio_ctx, long nr, void *iocbpp)
{
	if (!mep_proc_wanted())
		return 0;
	struct fs_event *e = gadget_reserve_buf(&fs_events, sizeof(*e));
	if (!e)
		return 0;
	e->timestamp_raw = bpf_ktime_get_boot_ns();
	gadget_process_populate(&e->proc);
	e->fs_op_raw = fs_io_submit;
	e->count = (nr < 0) ? 0 : (__u64)nr;	// iocbs submitted this call
	e->retval = 0;
	e->fname[0] = '\0';
	gadget_submit_buf(ctx, &fs_events, e, sizeof(*e));
	return 0;
}

// ---------------------------------------------------------------- block_io --
// Block-I/O subsystem. Per-request latency from issue->completion keyed by the
// request pointer, with the device + sector + byte count + R/W direction. This
// is the block-device saturation signal: rising per-I/O latency under a deep queue.
// Mirrors the in-tree top_blockio attach points (kprobe blk_mq_start_request +
// tp_btf/block_io_done) but STREAMS per-I/O events instead of aggregating.
struct blk_event {
	gadget_timestamp timestamp_raw;
	struct gadget_process proc;
	__u32 dev;		// dev_t (major:minor)
	__u64 sector;
	__u64 bytes;
	gadget_duration latency_ns;	// issue -> done
	__u8  is_write;
	__u8  req_op;		// [ENRICH] REQ_OP_* (0=READ 1=WRITE 2=FLUSH 3=DISCARD 9=WRITE_ZEROES...) — explains bytes==0 (FLUSH/barrier carry no payload)
	__u16 queue_depth;	// [ENRICH] in-flight block requests (device queue depth) this I/O observed at issue — makes a "deep queue" measurable next to latency_ns
};

GADGET_TRACER_MAP(blk_events, 1024 * 256);
GADGET_TRACER(mep_blk, blk_events, blk_event);

struct blk_start { __u64 ts; struct gadget_process proc; __u64 depth; };
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, __u64);	// struct request *
	__type(value, struct blk_start);
} blk_inflight SEC(".maps");

// system-wide in-flight block-request counter (queue depth gauge). Incremented
// at issue (block_io_start), decremented at completion (block_io_done). The
// depth a request SAW at issue is stamped into its event so a deep device queue
// becomes directly observable alongside the per-I/O latency.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} blk_depth SEC(".maps");

// tp_btf/block_io_start fires when a request is issued to the driver; the
// request pointer is the BTF-typed first arg. We record the issue timestamp +
// issuing process keyed by the request pointer. (blk_account_io_done is inlined
// on 6.17 and absent from kallsyms, so we use the BTF tracepoints — the same
// attach points the in-tree top_blockio gadget uses.)
SEC("tp_btf/block_io_start")
int BPF_PROG(mep_blk_start, struct request *rq)
{
	struct blk_start s = {};
	s.ts = bpf_ktime_get_boot_ns();
	gadget_process_populate(&s.proc);
	__u32 zk = 0;
	__u64 *dp = bpf_map_lookup_elem(&blk_depth, &zk);
	if (dp) {
		__sync_fetch_and_add(dp, 1);
		s.depth = *dp;		// queue depth this request saw at issue
	}
	__u64 key = (__u64)rq;
	bpf_map_update_elem(&blk_inflight, &key, &s, BPF_ANY);
	return 0;
}

SEC("tp_btf/block_io_done")
int BPF_PROG(mep_blk_done, struct request *rq)
{
	__u64 key = (__u64)rq;
	struct blk_start *s = bpf_map_lookup_elem(&blk_inflight, &key);
	if (!s) return 0;
	__u64 lat = bpf_ktime_get_boot_ns() - s->ts;
	__u32 zk = 0;
	__u64 *dp = bpf_map_lookup_elem(&blk_depth, &zk);
	if (dp)
		__sync_fetch_and_add(dp, (__u64)-1);	// completion: one fewer in flight
	struct blk_event *e = gadget_reserve_buf(&blk_events, sizeof(*e));
	if (!e) { bpf_map_delete_elem(&blk_inflight, &key); return 0; }
	e->timestamp_raw = bpf_ktime_get_boot_ns();
	e->proc = s->proc;
	struct request *r = rq;
	__u32 dev = 0; __u64 sector = 0; unsigned int data_len = 0; unsigned int cmd_flags = 0;
	struct gendisk *disk = get_disk(r);
	if (disk) {
		__u32 major = BPF_CORE_READ(disk, major);
		__u32 first_minor = BPF_CORE_READ(disk, first_minor);
		dev = (major << 20) | first_minor;
	}
	sector = BPF_CORE_READ(r, __sector);
	data_len = BPF_CORE_READ(r, __data_len);
	cmd_flags = BPF_CORE_READ(r, cmd_flags);
	e->dev = dev;
	e->sector = sector;
	e->bytes = data_len;
	e->latency_ns = lat;
	e->queue_depth = (__u16)s->depth;
	__u8 op = (__u8)(cmd_flags & ((1 << 8) - 1)); // REQ_OP_MASK low 8 bits
	e->req_op = op;
	e->is_write = (op == 1) ? 1 : 0; // REQ_OP_WRITE==1
	bpf_map_delete_elem(&blk_inflight, &key);
	gadget_submit_buf(ctx, &blk_events, e, sizeof(*e));
	return 0;
}

// ---------------------------------------------------------------- runq_lat --
// Scheduler subsystem. Run-queue latency = time a task spends RUNNABLE on the
// rq before it is scheduled onto a CPU (wakeup/enqueue -> on-cpu). High runqlat
// is the classic "the box is fine but my service is slow / hangs" signal,
// localizing to CPU saturation rather than the application. Measured
// as ttwu_do_activate (enqueue ts) -> sched_switch (next task on-cpu) delta,
// keyed by the woken pid. Robust bcc pattern (avoids the templated wakeup tp).
struct runq_event {
	gadget_timestamp timestamp_raw;
	struct gadget_process proc;
	gadget_duration runq_ns;		// enqueue -> on-cpu latency
	__u32 cpu;		// cpu the task landed on
};

GADGET_TRACER_MAP(runq_events, 1024 * 256);
GADGET_TRACER(mep_runq, runq_events, runq_event);

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u32);	// pid being woken
	__type(value, __u64);	// enqueue ts
} runq_enq SEC(".maps");

// void ttwu_do_activate(struct rq *rq, struct task_struct *p, int wake_flags,...)
SEC("kprobe/ttwu_do_activate")
int BPF_KPROBE(mep_runq_enqueue, void *rq, struct task_struct *p)
{
	__u32 pid = BPF_CORE_READ(p, pid);
	if (pid == 0) return 0;
	__u64 ts = bpf_ktime_get_boot_ns();
	bpf_map_update_elem(&runq_enq, &pid, &ts, BPF_ANY);
	return 0;
}

SEC("tracepoint/sched/sched_switch")
int mep_runq_switch(struct trace_event_raw_sched_switch *ctx)
{
	__u32 next_pid = ctx->next_pid;
	if (next_pid == 0) return 0;
	__u64 *tsp = bpf_map_lookup_elem(&runq_enq, &next_pid);
	if (!tsp) return 0;
	__u64 lat = bpf_ktime_get_boot_ns() - *tsp;
	bpf_map_delete_elem(&runq_enq, &next_pid);
	struct runq_event *e = gadget_reserve_buf(&runq_events, sizeof(*e));
	if (!e) return 0;
	e->timestamp_raw = bpf_ktime_get_boot_ns();
	gadget_process_populate(&e->proc);
	e->runq_ns = lat;
	e->cpu = bpf_get_smp_processor_id();
	gadget_submit_buf(ctx, &runq_events, e, sizeof(*e));
	return 0;
}

// ===========================================================================
// ---- cross-capability join: most-recent per-PID GPU SM utilization ---------
// cuda_smutil writes each PID's recent SM% here on every NVML
// ProcessUtilization return; cuda_memsnapshot reads it to DERIVE, in-kernel,
// reserved_unused_bytes — VRAM a PID holds while it is doing ~0% GPU compute.
// This is a real measured join across two NVML uretprobes (not a static label).
struct gpu_sm_sample {
	__u32 sm_util;	// most-recent SM (compute) % for this pid
	__u64 ts;	// bpf_ktime_get_boot_ns() when recorded (freshness)
};
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);		// gpu pid
	__type(value, struct gpu_sm_sample);
} gpu_sm_recent SEC(".maps");
#define GPU_SM_IDLE_THRESH  5                       // <=5% recent SM == idle
#define GPU_SM_FRESH_NS     (5ULL * 1000000000ULL)  // 5s freshness window

// cuda_memsnapshot — STANDING per-PID GPU memory residency gauge (NVML)
// ---------------------------------------------------------------------------
// WHY THIS EXISTS (closed-loop capability gap):
// The event-delta family (cuda_memtrace) traces alloc/free as they happen.
// A process that RESERVES a large VRAM pool ONCE at startup — before any
// observation window — emits ZERO alloc/free events during capture, so the
// delta tracer is structurally blind to "reserved >> used" over-allocation.
// A SNAPSHOT is needed here: the current standing reservation per PID, not a
// stream of deltas. This capability provides exactly that.
//
// MECHANISM (read-only, piggyback on any NVML consumer — nvidia-smi, dcgm):
// uprobe nvmlDeviceGetComputeRunningProcesses_v3(dev, *count, infos[]):
// stash the caller's count_ptr + infos_ptr (per tid).
// uretprobe (ret==0): read *count, walk the nvmlProcessInfo_v3_t[] array,
// emit one snapshot event per running PID with its usedGpuMemory.
// uretprobe nvmlDeviceGetMemoryInfo_v2(dev, *mem): emit device total/free/used.
//
// nvmlProcessInfo_v3_t layout (NVML >= R510):
// unsigned int pid; // @0
// unsigned long long usedGpuMemory; // @8 (8-aligned -> 4 bytes pad @4)
// unsigned int gpuInstanceId; // @16
// unsigned int computeInstanceId; // @20
// => stride 24 bytes; pid@0, usedGpuMemory@8.
//
// nvmlMemory_v2_t layout:
// unsigned int version; // @0
// (4 pad)
// unsigned long long total; // @8
// unsigned long long reserved; // @16
// unsigned long long free; // @24
// unsigned long long used; // @32
//
// READ-ONLY: pure observation; never alters NVML returns or buffers.
// ===========================================================================

enum memsnap_op {
	memsnap_proc,	// per-PID standing residency row (pid + used_gpu_mem)
	memsnap_device,	// device-wide total/free/used gauge
};

struct memsnap_event {
	gadget_timestamp timestamp_raw;
	struct gadget_process proc;	// the NVML CALLER (e.g. nvidia-smi/dcgm)

	enum memsnap_op memsnap_op_raw;
	__u8  pad[4];
	__u32 gpu_pid;			// the PID that HOLDS the memory (from NVML table)
	__u64 used_gpu_mem;		// bytes this PID currently reserves on the GPU
	__u64 dev_total;		// device: total bytes (memsnap_device only)
	__u64 dev_free;			// device: free bytes
	__u64 dev_used;			// device: used bytes
	__u32 recent_sm_util;		// most-recent externally-sampled SM%% for gpu_pid (0 = no recent compute)
	__u32 pad2;
	__u64 reserved_unused_bytes;	// VRAM gpu_pid holds while recent SM ~0%% (idle reservation); 0 if computing
};

GADGET_TRACER_MAP(memsnap_events, 1024 * 64);
GADGET_TRACER(mep_memsnap, memsnap_events, memsnap_event);

// per-tid stash of the NVML output-buffer pointers captured on uprobe entry
struct memsnap_ctx {
	__u64 count_ptr;	// unsigned int *count
	__u64 infos_ptr;	// nvmlProcessInfo_v3_t *infos
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);		// tid
	__type(value, struct memsnap_ctx);
} memsnap_pending SEC(".maps");

// per-tid stash of the nvmlMemory_v2_t* for the device gauge
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);		// tid
	__type(value, __u64);		// nvmlMemory_v2_t *mem
} memsnap_mem_pending SEC(".maps");

#define NVML_PROCINFO_V3_STRIDE 24
#define NVML_PROCINFO_PID_OFF    0
#define NVML_PROCINFO_USED_OFF   8
#define MEMSNAP_MAX_PROCS        64	// bounded loop for the verifier

// ---- compute-running-processes: capture output pointers on entry -----------
// int nvmlDeviceGetComputeRunningProcesses_v3(dev, unsigned int *count,
// nvmlProcessInfo_v3_t *infos)
SEC("uprobe/libnvidia-ml:nvmlDeviceGetComputeRunningProcesses_v3")
int BPF_UPROBE(mep_memsnap_procs_enter, void *dev, void *count, void *infos)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	struct memsnap_ctx c = {};
	c.count_ptr = (__u64)count;
	c.infos_ptr = (__u64)infos;
	bpf_map_update_elem(&memsnap_pending, &tid, &c, BPF_ANY);
	return 0;
}

// ---- on return: walk the filled array, emit one row per holding PID --------
SEC("uretprobe/libnvidia-ml:nvmlDeviceGetComputeRunningProcesses_v3")
int BPF_URETPROBE(mep_memsnap_procs_ret, long ret)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	struct memsnap_ctx *c = bpf_map_lookup_elem(&memsnap_pending, &tid);
	if (!c)
		return 0;
	__u64 count_ptr = c->count_ptr;
	__u64 infos_ptr = c->infos_ptr;
	bpf_map_delete_elem(&memsnap_pending, &tid);

	// NVML_SUCCESS == 0. On INSUFFICIENT_SIZE the count is updated but infos
	// not filled — only decode on clean success.
	if (ret != 0)
		return 0;
	if (!count_ptr || !infos_ptr)
		return 0;

	__u32 n = 0;
	bpf_probe_read_user(&n, sizeof(n), (void *)count_ptr);
	if (n == 0)
		return 0;
	if (n > MEMSNAP_MAX_PROCS)
		n = MEMSNAP_MAX_PROCS;

	if (!mep_proc_wanted())
		return 0;

	#pragma unroll
	for (int i = 0; i < MEMSNAP_MAX_PROCS; i++) {
		if (i >= n)
			break;
		__u64 base = infos_ptr + (__u64)i * NVML_PROCINFO_V3_STRIDE;
		__u32 gpu_pid = 0;
		__u64 used = 0;
		bpf_probe_read_user(&gpu_pid, sizeof(gpu_pid),
				    (void *)(base + NVML_PROCINFO_PID_OFF));
		bpf_probe_read_user(&used, sizeof(used),
				    (void *)(base + NVML_PROCINFO_USED_OFF));
		if (gpu_pid == 0)
			continue;

		struct memsnap_event *e =
			gadget_reserve_buf(&memsnap_events, sizeof(*e));
		if (!e)
			return 0;
		e->timestamp_raw = bpf_ktime_get_boot_ns();
		gadget_process_populate(&e->proc);
		e->memsnap_op_raw = memsnap_proc;
		e->gpu_pid = gpu_pid;
		e->used_gpu_mem = used;
		e->dev_total = 0;
		e->dev_free = 0;
		e->dev_used = 0;

		// DERIVED join: is this holding PID actually computing? Look up its
		// most-recent SM% (written by cuda_smutil). A PID that holds VRAM but
		// shows ~0% recent SM (or has no recent compute sample at all) is
		// holding reserved-but-unused memory -> reserved_unused_bytes = used.
		__u32 recent_sm = 0;
		__u64 unused = used;	// default: no recent compute seen -> all held VRAM idle
		struct gpu_sm_sample *smp = bpf_map_lookup_elem(&gpu_sm_recent, &gpu_pid);
		if (smp) {
			__u64 nowts = bpf_ktime_get_boot_ns();
			if (nowts - smp->ts < GPU_SM_FRESH_NS) {
				recent_sm = smp->sm_util;
				unused = (smp->sm_util <= GPU_SM_IDLE_THRESH) ? used : 0;
			}
		}
		e->recent_sm_util = recent_sm;
		e->pad2 = 0;
		e->reserved_unused_bytes = unused;
		gadget_submit_buf(ctx, &memsnap_events, e, sizeof(*e));
	}
	return 0;
}

// ---- device-wide gauge: nvmlDeviceGetMemoryInfo_v2(dev, nvmlMemory_v2_t*) ---
SEC("uprobe/libnvidia-ml:nvmlDeviceGetMemoryInfo_v2")
int BPF_UPROBE(mep_memsnap_dev_enter, void *dev, void *mem)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	__u64 memp = (__u64)mem;
	bpf_map_update_elem(&memsnap_mem_pending, &tid, &memp, BPF_ANY);
	return 0;
}

SEC("uretprobe/libnvidia-ml:nvmlDeviceGetMemoryInfo_v2")
int BPF_URETPROBE(mep_memsnap_dev_ret, long ret)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	__u64 *memp = bpf_map_lookup_elem(&memsnap_mem_pending, &tid);
	if (!memp)
		return 0;
	__u64 mem = *memp;
	bpf_map_delete_elem(&memsnap_mem_pending, &tid);

	if (ret != 0 || !mem)
		return 0;
	if (!mep_proc_wanted())
		return 0;

	// nvmlMemory_v2_t: version@0, total@8, reserved@16, free@24, used@32
	__u64 total = 0, free = 0, used = 0;
	bpf_probe_read_user(&total, sizeof(total), (void *)(mem + 8));
	bpf_probe_read_user(&free,  sizeof(free),  (void *)(mem + 24));
	bpf_probe_read_user(&used,  sizeof(used),  (void *)(mem + 32));

	struct memsnap_event *e = gadget_reserve_buf(&memsnap_events, sizeof(*e));
	if (!e)
		return 0;
	e->timestamp_raw = bpf_ktime_get_boot_ns();
	gadget_process_populate(&e->proc);
	e->memsnap_op_raw = memsnap_device;
	e->gpu_pid = 0;
	e->used_gpu_mem = 0;
	e->dev_total = total;
	e->dev_free = free;
	e->dev_used = used;
	e->recent_sm_util = 0;
	e->pad2 = 0;
	e->reserved_unused_bytes = 0;
	gadget_submit_buf(ctx, &memsnap_events, e, sizeof(*e));
	return 0;
}



// ===========================================================================
// cuda_smutil — STANDING per-PID GPU COMPUTE (SM) utilization gauge (NVML)
// ---------------------------------------------------------------------------
// WHY THIS EXISTS (closed-loop capability gap):
// cuda_memsnapshot answers "how much VRAM does each PID HOLD". But the F2
// over-allocation analysis also needs the orthogonal axis: "is that PID actually
// USING the GPU compute units, or just squatting on memory?". Kernel-launch
// COUNTS (cuda_profile) are a weak proxy — a PID can launch many tiny kernels
// yet drive ~0% SM, or launch few huge ones at 100% SM. The DIRECT hardware
// signal is per-PID SM-occupancy %, which NVML exposes via
// nvmlDeviceGetProcessUtilization(). With it, "idle-held (SM~0%) VRAM" is proven
// directly: PID holds N GiB AND smUtil==0% -> reclaimable.
//
// MECHANISM (read-only, piggyback on any NVML consumer — nvidia-smi, dcgm,
// the cluster's per-PID GPU accounting daemon):
// int nvmlDeviceGetProcessUtilization(dev,
// nvmlProcessUtilizationSample_t *utilization, // arg1 (out buf)
// unsigned int *processSamplesCount, // arg2 (in/out)
// unsigned long long lastSeenTimeStamp) // arg3
// uprobe : stash utilization_ptr (arg1) + count_ptr (arg2) per tid.
// uretprobe (ret==0): read *count, walk the sample[] array, emit one row per
// PID with its smUtil/memUtil percentages.
//
// nvmlProcessUtilizationSample_t layout (NVML R384+):
// unsigned int pid; // @0
// (4 bytes pad @4 — next field is 8-aligned)
// unsigned long long timeStamp; // @8
// unsigned int smUtil; // @16 (% SM active for this PID)
// unsigned int memUtil; // @20 (% framebuffer BW for this PID)
// unsigned int encUtil; // @24
// unsigned int decUtil; // @28
// => stride 32 bytes; pid@0, smUtil@16, memUtil@20.
//
// READ-ONLY: pure observation; never alters NVML returns or buffers.
// ===========================================================================

enum smutil_op {
	smutil_proc,	// per-PID SM/compute utilization row
};

struct smutil_event {
	gadget_timestamp timestamp_raw;
	struct gadget_process proc;	// the NVML caller (nvidia-smi/dcgm)

	enum smutil_op smutil_op_raw;
	__u32 smu_pid;			// the PID whose SM utilization this is
	__u32 sm_util;			// % SM (compute) active for this PID
	__u32 mem_util;			// % framebuffer bandwidth for this PID
};

GADGET_TRACER_MAP(smutil_events, 1024 * 64);
GADGET_TRACER(mep_smutil, smutil_events, smutil_event);

// per-tid stash of the NVML output-buffer pointers captured on uprobe entry
struct smutil_ctx {
	__u64 count_ptr;	// unsigned int *processSamplesCount
	__u64 util_ptr;		// nvmlProcessUtilizationSample_t *utilization
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);		// tid
	__type(value, struct smutil_ctx);
} smutil_pending SEC(".maps");

#define NVML_PROCUTIL_STRIDE   32
#define NVML_PROCUTIL_PID_OFF   0
#define NVML_PROCUTIL_SM_OFF   16
#define NVML_PROCUTIL_MEM_OFF  20
#define SMUTIL_MAX_PROCS       64	// bounded loop for the verifier

// ---- capture output pointers on entry --------------------------------------
// nvmlDeviceGetProcessUtilization(dev, utilization*, count*, lastSeenTs)
SEC("uprobe/libnvidia-ml:nvmlDeviceGetProcessUtilization")
int BPF_UPROBE(mep_smutil_enter, void *dev, void *utilization, void *count)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	struct smutil_ctx c = {};
	c.util_ptr = (__u64)utilization;
	c.count_ptr = (__u64)count;
	bpf_map_update_elem(&smutil_pending, &tid, &c, BPF_ANY);
	return 0;
}

// ---- on return: walk the filled array, emit one row per PID ----------------
SEC("uretprobe/libnvidia-ml:nvmlDeviceGetProcessUtilization")
int BPF_URETPROBE(mep_smutil_ret, long ret)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	struct smutil_ctx *c = bpf_map_lookup_elem(&smutil_pending, &tid);
	if (!c)
		return 0;
	__u64 count_ptr = c->count_ptr;
	__u64 util_ptr = c->util_ptr;
	bpf_map_delete_elem(&smutil_pending, &tid);

	// NVML_SUCCESS == 0. On INSUFFICIENT_SIZE count is updated but the buffer
	// is NOT filled — only decode on clean success.
	if (ret != 0)
		return 0;
	if (!count_ptr || !util_ptr)
		return 0;

	__u32 n = 0;
	bpf_probe_read_user(&n, sizeof(n), (void *)count_ptr);
	if (n == 0)
		return 0;
	if (n > SMUTIL_MAX_PROCS)
		n = SMUTIL_MAX_PROCS;

	if (!mep_proc_wanted())
		return 0;

	#pragma unroll
	for (int i = 0; i < SMUTIL_MAX_PROCS; i++) {
		if (i >= n)
			break;
		__u64 base = util_ptr + (__u64)i * NVML_PROCUTIL_STRIDE;
		__u32 smu_pid = 0, sm = 0, mem = 0;
		bpf_probe_read_user(&smu_pid, sizeof(smu_pid),
				    (void *)(base + NVML_PROCUTIL_PID_OFF));
		bpf_probe_read_user(&sm, sizeof(sm),
				    (void *)(base + NVML_PROCUTIL_SM_OFF));
		bpf_probe_read_user(&mem, sizeof(mem),
				    (void *)(base + NVML_PROCUTIL_MEM_OFF));
		if (smu_pid == 0)
			continue;

		struct smutil_event *e =
			gadget_reserve_buf(&smutil_events, sizeof(*e));
		if (!e)
			return 0;
		e->timestamp_raw = bpf_ktime_get_boot_ns();
		gadget_process_populate(&e->proc);
		e->smutil_op_raw = smutil_proc;
		e->smu_pid = smu_pid;
		e->sm_util = sm;
		e->mem_util = mem;
		gadget_submit_buf(ctx, &smutil_events, e, sizeof(*e));

		// publish this PID's recent SM% for the cuda_memsnapshot join
		struct gpu_sm_sample samp = {};
		samp.sm_util = sm;
		samp.ts = bpf_ktime_get_boot_ns();
		bpf_map_update_elem(&gpu_sm_recent, &smu_pid, &samp, BPF_ANY);
	}
	return 0;
}

// ===========================================================================
// [epoll_timer] epoll_timer — event-loop causal-chain visibility. Surfaces the
// timerfd/hrtimer arm+fire lifecycle, epoll_ctl registration (incl EPOLLRDHUP
// peer-close interest) and epoll_wait enter/exit (nready==0 == timeout: the
// "app woke on nothing" vs "kernel never armed the timer" discriminator).
// Targets event-loop stalls: SSE/keepalive misses and timer-arm races.
// ===========================================================================
enum mep_timer_kind {
	timer_timerfd_set   = 1,	// app armed/disarmed a timerfd (sys_enter_timerfd_settime)
	timer_epoll_ctl_add = 2,	// EPOLL_CTL_ADD — registered fd interest
	timer_epoll_ctl_mod = 3,	// EPOLL_CTL_MOD
	timer_epoll_ctl_del = 4,	// EPOLL_CTL_DEL
	timer_epoll_wait    = 5,	// entered epoll_wait (blocking the loop)
	timer_epoll_ret     = 6,	// epoll_wait returned (nready; 0 == TIMEOUT)
	timer_hrtimer_arm   = 7,	// kernel armed an hrtimer for this proc
	timer_hrtimer_fire  = 8,	// kernel fired that hrtimer (softirq, ptr-correlated)
};

struct timer_event {
	gadget_timestamp timestamp_raw;
	struct gadget_process proc;
	enum mep_timer_kind kind_raw;
	__s32 fd;			// epoll/timer fd (epfd for wait/ctl, tfd for timerfd); -1 hrtimer
	__s32 nready;			// epoll_wait return: #ready fds; 0 == TIMEOUT; -1 on enter row
	__u32 ev_mask;			// epoll interest mask (EPOLLRDHUP=0x2000 => peer-close aware)
	__u32 op;			// EPOLL_CTL op / timerfd flags / epoll_wait timeout(ms)
	__u64 expires_ns;		// hrtimer deadline / fire ktime / timerfd it_value (0==disarm)
	__u64 timer_ptr;		// hrtimer address (arm<->fire correlation key)
};
GADGET_TRACER_MAP(timer_events, 128 * 1024);
GADGET_TRACER(mep_timer, timer_events, timer_event);

// hrtimers armed by a wanted process, keyed by hrtimer address, so the
// softirq-context expire tracepoint (running in the WRONG task context) can
// still attribute the fire to the arming process AND bound emission to only
// the target's timers instead of the whole system.
struct mep_timer_owner {
	__u32 tgid;
	__u64 arm_ts;
	char  comm[16];
};
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, __u64);			// hrtimer ptr
	__type(value, struct mep_timer_owner);
} mep_timer_armed SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_timerfd_settime")
int mep_timer_timerfd(struct trace_event_raw_sys_enter *ctx)
{
	if (!mep_proc_wanted())
		return 0;
	struct timer_event *e = gadget_reserve_buf(&timer_events, sizeof(*e));
	if (!e)
		return 0;
	e->timestamp_raw = bpf_ktime_get_boot_ns();
	gadget_process_populate(&e->proc);
	e->kind_raw = timer_timerfd_set;
	e->fd = (int)ctx->args[0];		// timer fd
	e->op = (__u32)ctx->args[1];		// flags (1==TFD_TIMER_ABSTIME)
	e->nready = 0;
	e->ev_mask = 0;
	e->timer_ptr = 0;
	// args[2] = const struct itimerspec *new_value. timespec is {tv_sec@0, tv_nsec@8}
	// (8+8 on amd64) so it_value (2nd timespec) lives at offset 16. it_value=={0,0}
	// means DISARM — the "app cancelled its keepalive/idle timer" signal.
	__u64 v_sec = 0, v_nsec = 0;
	const void *nv = (const void *)ctx->args[2];
	if (nv) {
		bpf_probe_read_user(&v_sec,  sizeof(v_sec),  nv + 16);
		bpf_probe_read_user(&v_nsec, sizeof(v_nsec), nv + 24);
	}
	e->expires_ns = v_sec * 1000000000ULL + v_nsec;
	gadget_submit_buf(ctx, &timer_events, e, sizeof(*e));
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_epoll_ctl")
int mep_timer_epoll_ctl(struct trace_event_raw_sys_enter *ctx)
{
	if (!mep_proc_wanted())
		return 0;
	int op = (int)ctx->args[1];		// EPOLL_CTL_ADD=1 DEL=2 MOD=3
	struct timer_event *e = gadget_reserve_buf(&timer_events, sizeof(*e));
	if (!e)
		return 0;
	e->timestamp_raw = bpf_ktime_get_boot_ns();
	gadget_process_populate(&e->proc);
	e->kind_raw = (op == 2) ? timer_epoll_ctl_del :
	              (op == 3) ? timer_epoll_ctl_mod : timer_epoll_ctl_add;
	e->fd = (int)ctx->args[2];		// fd being (de)registered
	e->op = (__u32)op;
	e->nready = 0;
	e->expires_ns = 0;
	e->timer_ptr = (__u64)(__u32)ctx->args[0];	// epfd as loose correlation handle
	// args[3] = struct epoll_event *; the interest mask is the leading __u32.
	__u32 mask = 0;
	const void *ev = (const void *)ctx->args[3];
	if (ev && op != 2)			// DEL ignores the event ptr
		bpf_probe_read_user(&mask, sizeof(mask), ev);
	e->ev_mask = mask;			// bit 0x2000 (EPOLLRDHUP) => peer-close aware
	gadget_submit_buf(ctx, &timer_events, e, sizeof(*e));
	return 0;
}

static __always_inline int mep_timer_wait_enter(struct trace_event_raw_sys_enter *ctx)
{
	if (!mep_proc_wanted())
		return 0;
	struct timer_event *e = gadget_reserve_buf(&timer_events, sizeof(*e));
	if (!e)
		return 0;
	e->timestamp_raw = bpf_ktime_get_boot_ns();
	gadget_process_populate(&e->proc);
	e->kind_raw = timer_epoll_wait;
	e->fd = (int)ctx->args[0];		// epfd
	e->op = (__u32)ctx->args[3];		// timeout(ms); -1==block forever
	e->nready = -1;				// enter: outcome not known yet
	e->ev_mask = 0;
	e->expires_ns = 0;
	e->timer_ptr = 0;
	gadget_submit_buf(ctx, &timer_events, e, sizeof(*e));
	return 0;
}
SEC("tracepoint/syscalls/sys_enter_epoll_pwait")
int mep_timer_epoll_pwait_enter(struct trace_event_raw_sys_enter *ctx)
{ return mep_timer_wait_enter(ctx); }
SEC("tracepoint/syscalls/sys_enter_epoll_wait")
int mep_timer_epoll_wait_enter(struct trace_event_raw_sys_enter *ctx)
{ return mep_timer_wait_enter(ctx); }

static __always_inline int mep_timer_wait_exit(struct trace_event_raw_sys_exit *ctx)
{
	if (!mep_proc_wanted())
		return 0;
	struct timer_event *e = gadget_reserve_buf(&timer_events, sizeof(*e));
	if (!e)
		return 0;
	e->timestamp_raw = bpf_ktime_get_boot_ns();
	gadget_process_populate(&e->proc);
	e->kind_raw = timer_epoll_ret;
	e->fd = 0;
	e->op = 0;
	e->nready = (int)ctx->ret;		// #ready fds; 0 == TIMEOUT (woke on nothing)
	e->ev_mask = 0;
	e->expires_ns = 0;
	e->timer_ptr = 0;
	gadget_submit_buf(ctx, &timer_events, e, sizeof(*e));
	return 0;
}
SEC("tracepoint/syscalls/sys_exit_epoll_pwait")
int mep_timer_epoll_pwait_exit(struct trace_event_raw_sys_exit *ctx)
{ return mep_timer_wait_exit(ctx); }
SEC("tracepoint/syscalls/sys_exit_epoll_wait")
int mep_timer_epoll_wait_exit(struct trace_event_raw_sys_exit *ctx)
{ return mep_timer_wait_exit(ctx); }

SEC("tracepoint/timer/hrtimer_start")
int mep_timer_hrtimer_start(struct trace_event_raw_hrtimer_start *ctx)
{
	// hrtimer_start mostly fires in the ARMING task's context (from the
	// timerfd_settime/nanosleep syscall) so the pid gate is meaningful here.
	if (!mep_proc_wanted())
		return 0;
	__u64 ptr = (__u64)ctx->hrtimer;
	struct mep_timer_owner ow = {};
	ow.tgid = bpf_get_current_pid_tgid() >> 32;
	ow.arm_ts = bpf_ktime_get_boot_ns();
	bpf_get_current_comm(&ow.comm, sizeof(ow.comm));
	bpf_map_update_elem(&mep_timer_armed, &ptr, &ow, BPF_ANY);
	struct timer_event *e = gadget_reserve_buf(&timer_events, sizeof(*e));
	if (!e)
		return 0;
	e->timestamp_raw = ow.arm_ts;
	gadget_process_populate(&e->proc);
	e->kind_raw = timer_hrtimer_arm;
	e->fd = -1;
	e->op = 0;
	e->nready = 0;
	e->ev_mask = 0;
	e->expires_ns = (__u64)ctx->expires;	// absolute kernel-time deadline
	e->timer_ptr = ptr;
	gadget_submit_buf(ctx, &timer_events, e, sizeof(*e));
	return 0;
}

SEC("tracepoint/timer/hrtimer_expire_entry")
int mep_timer_hrtimer_expire(struct trace_event_raw_hrtimer_expire_entry *ctx)
{
	// Runs in softirq: current task is NOT the owner. Correlate by the hrtimer
	// address recorded at arm-time to (a) attribute to the correct process and
	// (b) bound emission to only the target's timers.
	__u64 ptr = (__u64)ctx->hrtimer;
	struct mep_timer_owner *ow = bpf_map_lookup_elem(&mep_timer_armed, &ptr);
	if (!ow)
		return 0;
	struct timer_event *e = gadget_reserve_buf(&timer_events, sizeof(*e));
	if (!e)
		return 0;
	e->timestamp_raw = bpf_ktime_get_boot_ns();
	__builtin_memset(&e->proc, 0, sizeof(e->proc));
	e->proc.pid = ow->tgid;			// attribute to the arming process
	e->proc.tid = ow->tgid;
	__builtin_memcpy(&e->proc.comm, ow->comm, sizeof(e->proc.comm));
	e->kind_raw = timer_hrtimer_fire;
	e->fd = -1;
	e->op = 0;
	e->nready = 0;
	e->ev_mask = 0;
	e->expires_ns = (__u64)ctx->now;	// when it actually fired
	e->timer_ptr = ptr;
	gadget_submit_buf(ctx, &timer_events, e, sizeof(*e));
	bpf_map_delete_elem(&mep_timer_armed, &ptr);
	return 0;
}

// ===========================================================================
// [absence_assert] absence_assert -- negative / proof-of-ABSENCE primitive.
// The event families are PRESENCE-oriented (they emit when something happens);
// proving an EXPECTED event did NOT happen -- e.g. a ~15s SSE keepalive that
// never fired on an idle-but-ESTABLISHED socket (an event-loop race) -- must be judged at
// FETCH time against the wall clock, which no submit-hook can see. This
// iter/tcp walk visits EVERY live TCP socket on demand and cross-references the
// per-flow write history per_key_rollup's net_rollup_map already maintains, returning a
// single PASS/FAIL verdict per flow. Socket-state-anchored (state off the live
// sock) so "it just closed" / "it wasn't idle" counter-explanations are ruled
// out in the same row. Reuses the proven iter/tcp path (sock_snapshot sock_snapshot);
// needs --host; arm via the absence_period_ns / absence_jitter_ns params.
const volatile __u64 absence_period_ns = 0;	// expected inter-write period (ns); 0 = unarmed/observational
GADGET_PARAM(absence_period_ns);
const volatile __u64 absence_jitter_ns = 0;	// allowed slop added to the period before FAIL_SILENT
GADGET_PARAM(absence_jitter_ns);

enum mep_absence_verdict {
	ABSENCE_INFO           = 0,	// unarmed (period==0): observational row only
	ABSENCE_PASS           = 1,	// armed: last write within period+jitter
	ABSENCE_FAIL_SILENT    = 2,	// armed: no write for > period+jitter (expected write never fired)
	ABSENCE_FAIL_AFTER_FIN = 3,	// write/IO seen during peer-FIN teardown (write-after-FIN)
	ABSENCE_NO_HISTORY     = 4,	// live socket but no net_rollup write row (select net_trace too)
};

struct absence_entry {
	__u32 saddr;			// local IPv4 (network order)
	__u32 daddr;			// remote IPv4 (network order)
	__u16 sport;			// local port (host order)
	__u16 dport;			// remote port (host order)
	__u16 family;			// AF_INET(2) / AF_INET6(10)
	__u16 state;			// current TCP state off the live sock
	__u8  verdict;			// enum mep_absence_verdict
	__u64 expected_period_ns;	// the armed period (0 = unarmed)
	__u64 last_write_gap_ns;	// now - last write on this flow (staleness)
	__u64 observed_max_gap_ns;	// largest inter-write gap ever seen (net_rollup gap_max)
	__u64 write_count;		// writes/net events folded into this flow (net_rollup count)
	__u64 closing_evts;		// writes during teardown -- write-after-peer-FIN shape
};

GADGET_ITER(mep_absence, absence_entry, mep_absence);

SEC("iter/tcp")
int mep_absence(struct bpf_iter__tcp *ctx)
{
	struct sock_common *skc = ctx->sk_common;
	struct seq_file *seq = ctx->meta->seq;
	struct absence_entry e = {};

	if (skc == NULL)
		return 0;

	__u16 st = BPF_CORE_READ(skc, skc_state);
	if (st == 0)			// skip TIME_WAIT/uninit shells with no state
		return 0;

	e.saddr  = BPF_CORE_READ(skc, skc_rcv_saddr);
	e.daddr  = BPF_CORE_READ(skc, skc_daddr);
	e.sport  = BPF_CORE_READ(skc, skc_num);			// already host order
	e.dport  = bpf_ntohs(BPF_CORE_READ(skc, skc_dport));	// net -> host
	e.family = BPF_CORE_READ(skc, skc_family);
	e.state  = st;
	e.expected_period_ns = absence_period_ns;

	if (e.family != 2)		// AF_INET only: net_rollup keys are IPv4 4-tuples
		return 0;

	struct net_rollup_key k = {};
	k.daddr = e.daddr; k.saddr = e.saddr;
	k.dport = e.dport; k.sport = e.sport;
	struct net_rollup_val *v = bpf_map_lookup_elem(&net_rollup_map, &k);

	if (!v || v->count == 0) {
		e.verdict = ABSENCE_NO_HISTORY;
		bpf_seq_write(seq, &e, sizeof(e));
		return 0;
	}

	e.write_count         = v->count;
	e.observed_max_gap_ns = v->gap_max_ns;
	e.closing_evts        = v->closing_evts;

	__u64 now = bpf_ktime_get_boot_ns();
	__u64 gap = now - v->last_ts_raw;
	e.last_write_gap_ns = gap;

	if (v->closing_evts > 0)
		e.verdict = ABSENCE_FAIL_AFTER_FIN;		// affirmative wrongness wins
	else if (absence_period_ns == 0)
		e.verdict = ABSENCE_INFO;			// unarmed: observational
	else if (gap > absence_period_ns + absence_jitter_ns)
		e.verdict = ABSENCE_FAIL_SILENT;		// expected write never fired
	else
		e.verdict = ABSENCE_PASS;

	bpf_seq_write(seq, &e, sizeof(e));
	return 0;
}
// ========================= [end absence_assert] absence_assert ======================

char LICENSE[] SEC("license") = "GPL";
