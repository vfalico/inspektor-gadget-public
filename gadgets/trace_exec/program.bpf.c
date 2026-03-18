// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define GADGET_NO_BUF_RESERVE
#include <gadget/buffer.h>
#include <gadget/common.h>
#include <gadget/filter.h>
#include <gadget/macros.h>
#include <gadget/types.h>
#include <gadget/filesystem.h>

// Defined in include/uapi/linux/magic.h
#define OVERLAYFS_SUPER_MAGIC 0x794c7630

#define ARGSIZE 256
#define TOTAL_MAX_ARGS 20

// Keep in sync with fullMaxArgsArr in program.go
#define FULL_MAX_ARGS_ARR (TOTAL_MAX_ARGS * ARGSIZE)

#define LAST_ARG (FULL_MAX_ARGS_ARR - ARGSIZE)

// Macros from https://github.com/torvalds/linux/blob/v6.12/include/linux/kdev_t.h#L7-L12
#define MINORBITS 20
#define MINORMASK ((1U << MINORBITS) - 1)
#define MAJOR(dev) ((unsigned int)((dev) >> MINORBITS))
#define MINOR(dev) ((unsigned int)((dev) & MINORMASK))
#define MKDEV(ma, mi) (((ma) << MINORBITS) | (mi))

// TLV field type IDs (must match ebpf.tlv.id in gadget.yaml)
#define TLV_CWD            1
#define TLV_FILE           2
#define TLV_EXEPATH        3
#define TLV_PARENT_EXEPATH 4

// TLV header: 4 bytes
struct gadget_tlv_hdr {
	__u16 type;
	__u16 length;
};
#define TLV_HDR_SIZE 4

/*
 * BTF-visible event struct: does NOT include path fields.
 * Path fields arrive as TLV entries after args.
 */
struct event {
	gadget_timestamp timestamp_raw;
	struct gadget_process proc;

	gadget_uid loginuid;
	__u32 sessionid;
	gadget_errno error_raw;
	int args_count;
	int tty;
	bool from_rootfs;
	bool file_from_rootfs;
	bool upper_layer;
	bool fupper_layer;
	bool pupper_layer;
	unsigned int args_size;
	unsigned int dev_major;
	unsigned int dev_minor;
	unsigned long inode;
	char args[FULL_MAX_ARGS_ARR];
};

/*
 * Internal storage struct with path fields for the BPF hash map.
 * Built across multiple tracepoints.
 */
struct event_store {
	gadget_timestamp timestamp_raw;
	struct gadget_process proc;
	gadget_uid loginuid;
	__u32 sessionid;
	gadget_errno error_raw;
	int args_count;
	int tty;
	bool from_rootfs;
	bool file_from_rootfs;
	bool upper_layer;
	bool fupper_layer;
	bool pupper_layer;
	unsigned int args_size;
	unsigned int dev_major;
	unsigned int dev_minor;
	unsigned long inode;
	char cwd[GADGET_PATH_MAX];
	char file[GADGET_PATH_MAX];
	char exepath[GADGET_PATH_MAX];
	char parent_exepath[GADGET_PATH_MAX];
	char args[FULL_MAX_ARGS_ARR];
};

#define BASE_EVENT_SIZE (size_t)(&((struct event *)0)->args)
#define EVENT_SIZE(e) (BASE_EVENT_SIZE + (e)->args_size)

const volatile bool ignore_failed = true;
const volatile bool paths = false;

GADGET_PARAM(ignore_failed);
GADGET_PARAM(paths);

static const struct event_store empty_event = {};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, pid_t);
	__type(value, struct event_store);
} execs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, pid_t);
	__type(value, __u8);
} security_bprm_hit_map SEC(".maps");

GADGET_TRACER_MAP(events, 1024 * 256);

GADGET_TRACER(exec, events, event);

// Maximum TLV payload: 4 path fields * (4-byte header + up to GADGET_PATH_MAX)
#define MAX_TLV_SIZE (4 * (TLV_HDR_SIZE + GADGET_PATH_MAX))

// Output buffer size
#define MAX_OUTPUT_SIZE (BASE_EVENT_SIZE + FULL_MAX_ARGS_ARR + MAX_TLV_SIZE + 64)

struct output_buf {
	char data[MAX_OUTPUT_SIZE];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct output_buf);
} output_heap SEC(".maps");

/*
 * append_tlv_path - Append a path as a TLV entry with fixed GADGET_PATH_MAX length.
 * Returns the new offset, or the original offset if the string is empty or doesn't fit.
 */
static __always_inline __u32
append_tlv_path(char *out, __u32 off, __u32 buf_size,
		__u16 type, const char *src)
{
	if (src[0] == '\0')
		return off;

	__u32 needed = TLV_HDR_SIZE + GADGET_PATH_MAX;
	if (off + needed > buf_size)
		return off;

	struct gadget_tlv_hdr *hdr = (struct gadget_tlv_hdr *)(out + off);
	hdr->type = type;
	hdr->length = GADGET_PATH_MAX;

	bpf_probe_read_kernel(out + off + TLV_HDR_SIZE, GADGET_PATH_MAX, src);
	return off + needed;
}

/*
 * submit_event - Assemble the output event and submit it.
 *
 * Layout: [struct event fields up to args][args (variable len)][TLV path entries]
 */
static __always_inline void submit_event(void *ctx, struct event_store *es)
{
	__u32 zero = 0;
	struct output_buf *ob = bpf_map_lookup_elem(&output_heap, &zero);
	if (!ob)
		return;

	char *out = ob->data;

	if (BASE_EVENT_SIZE > MAX_OUTPUT_SIZE)
		return;
	bpf_probe_read_kernel(out, BASE_EVENT_SIZE, es);

	__u32 off = BASE_EVENT_SIZE;

	__u32 args_size = es->args_size;
	if (args_size > FULL_MAX_ARGS_ARR)
		args_size = FULL_MAX_ARGS_ARR;
	if (off + args_size > MAX_OUTPUT_SIZE)
		return;

	bpf_probe_read_kernel(out + off, args_size, es->args);
	off += args_size;

	if (paths) {
		off = append_tlv_path(out, off, MAX_OUTPUT_SIZE,
				      TLV_CWD, es->cwd);
		off = append_tlv_path(out, off, MAX_OUTPUT_SIZE,
				      TLV_FILE, es->file);
		off = append_tlv_path(out, off, MAX_OUTPUT_SIZE,
				      TLV_EXEPATH, es->exepath);
		off = append_tlv_path(out, off, MAX_OUTPUT_SIZE,
				      TLV_PARENT_EXEPATH, es->parent_exepath);
	}

	if (off > 0 && off <= MAX_OUTPUT_SIZE)
		gadget_output_buf(ctx, &events, out, off);
}

static __always_inline int enter_execve(const char *pathname, const char **args)
{
	u64 id;
	pid_t pid;
	struct event_store *event;
	struct task_struct *task;
	unsigned int ret;
	const char *argp;
	int i;

	if (gadget_should_discard_data_current())
		return 0;

	id = bpf_get_current_pid_tgid();
	pid = (pid_t)id;
	if (bpf_map_update_elem(&execs, &pid, &empty_event, BPF_NOEXIST))
		return 0;

	event = bpf_map_lookup_elem(&execs, &pid);
	if (!event)
		return 0;

	event->timestamp_raw = bpf_ktime_get_boot_ns();
	task = (struct task_struct *)bpf_get_current_task();

	if (bpf_core_field_exists(task->loginuid))
		event->loginuid = BPF_CORE_READ(task, loginuid.val);
	else
		event->loginuid = 4294967295;

	if (bpf_core_field_exists(task->sessionid))
		event->sessionid = BPF_CORE_READ(task, sessionid);

	event->args_count = 0;
	event->args_size = 0;

	event->tty = BPF_CORE_READ(task, signal, tty, index);

	if (paths) {
		struct fs_struct *fs = BPF_CORE_READ(task, fs);
		char *cwd = get_path_str(&fs->pwd);
		bpf_probe_read_kernel_str(event->cwd, sizeof(event->cwd), cwd);
	}

	ret = bpf_probe_read_user_str(event->args, ARGSIZE, pathname);
	if (ret <= ARGSIZE) {
		event->args_size += ret;
	} else {
		event->args[0] = '\0';
		event->args_size++;
	}

	event->args_count++;
#pragma unroll
	for (i = 1; i < TOTAL_MAX_ARGS; i++) {
		bpf_probe_read_user(&argp, sizeof(argp), &args[i]);
		if (!argp)
			return 0;

		if (event->args_size > LAST_ARG)
			return 0;

		ret = bpf_probe_read_user_str(&event->args[event->args_size],
					      ARGSIZE, argp);
		if (ret > ARGSIZE)
			return 0;

		event->args_count++;
		event->args_size += ret;
	}
	bpf_probe_read_user(&argp, sizeof(argp), &args[TOTAL_MAX_ARGS]);
	if (!argp)
		return 0;

	event->args_count++;
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int ig_execve_e(struct syscall_trace_enter *ctx)
{
	const char *pathname = (const char *)ctx->args[0];
	const char **args = (const char **)(ctx->args[1]);
	return enter_execve(pathname, args);
}

SEC("tracepoint/syscalls/sys_enter_execveat")
int ig_execveat_e(struct syscall_trace_enter *ctx)
{
	const char *pathname = (const char *)ctx->args[1];
	const char **args = (const char **)(ctx->args[2]);
	return enter_execve(pathname, args);
}

static __always_inline bool __is_from_rootfs(struct task_struct *task,
					     struct file *file)
{
	struct vfsmount *file_mnt, *root_mnt;
	file_mnt = BPF_CORE_READ(file, f_path.mnt);
	root_mnt = BPF_CORE_READ(task, fs, root.mnt);
	return root_mnt == file_mnt;
}

static __always_inline bool is_from_rootfs(struct file *file)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	return __is_from_rootfs(task, file);
}

static __always_inline bool has_upper_layer(struct inode *inode)
{
	unsigned long sb_magic = BPF_CORE_READ(inode, i_sb, s_magic);
	if (sb_magic != OVERLAYFS_SUPER_MAGIC)
		return false;

	struct dentry *upperdentry;
	bpf_probe_read_kernel(&upperdentry, sizeof upperdentry,
			      ((void *)inode) +
				      bpf_core_type_size(struct inode));
	return upperdentry != NULL;
}

SEC("tracepoint/sched/sched_process_exec")
int ig_sched_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	u32 pre_sched_pid = ctx->old_pid;
	struct event_store *event;
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct task_struct *parent = BPF_CORE_READ(task, real_parent);

	event = bpf_map_lookup_elem(&execs, &pre_sched_pid);
	if (!event)
		return 0;

	struct inode *inode = BPF_CORE_READ(task, mm, exe_file, f_inode);
	if (inode)
		event->upper_layer = has_upper_layer(inode);

	struct inode *pinode = BPF_CORE_READ(parent, mm, exe_file, f_inode);
	if (pinode)
		event->pupper_layer = has_upper_layer(pinode);

	struct file *exe_file = BPF_CORE_READ(task, mm, exe_file);
	event->from_rootfs = __is_from_rootfs(task, exe_file);

	gadget_process_populate(&event->proc);
	event->error_raw = 0;

	if (paths) {
		char *exepath = get_path_str(&exe_file->f_path);
		bpf_probe_read_kernel_str(event->exepath,
					  sizeof(event->exepath), exepath);

		struct file *parent_exe_file =
			BPF_CORE_READ(parent, mm, exe_file);
		char *parent_exepath = get_path_str(&parent_exe_file->f_path);
		bpf_probe_read_kernel_str(event->parent_exepath,
					  sizeof(event->parent_exepath),
					  parent_exepath);
	}

	submit_event(ctx, event);

	bpf_map_delete_elem(&execs, &pre_sched_pid);
	bpf_map_delete_elem(&security_bprm_hit_map, &pre_sched_pid);

	return 0;
}

static __always_inline int exit_execve(void *ctx, int retval)
{
	u32 pid = (u32)bpf_get_current_pid_tgid();
	struct event_store *event;

	event = bpf_map_lookup_elem(&execs, &pid);
	if (!event)
		return 0;

	if (ignore_failed)
		goto cleanup;

	gadget_process_populate(&event->proc);
	event->error_raw = -retval;

	if (paths) {
		struct task_struct *task =
			(struct task_struct *)bpf_get_current_task();
		struct file *exe_file = BPF_CORE_READ(task, mm, exe_file);
		char *exepath = get_path_str(&exe_file->f_path);
		bpf_probe_read_kernel_str(event->exepath,
					  sizeof(event->exepath), exepath);
	}

	submit_event(ctx, event);
cleanup:
	bpf_map_delete_elem(&execs, &pid);
	bpf_map_delete_elem(&security_bprm_hit_map, &pid);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_execve")
int ig_execve_x(struct syscall_trace_exit *ctx)
{
	return exit_execve(ctx, ctx->ret);
}

SEC("tracepoint/syscalls/sys_exit_execveat")
int ig_execveat_x(struct syscall_trace_exit *ctx)
{
	return exit_execve(ctx, ctx->ret);
}

SEC("kprobe/security_bprm_check")
int BPF_KPROBE(security_bprm_check, struct linux_binprm *bprm)
{
	u32 pid = (u32)bpf_get_current_pid_tgid();
	struct event_store *event;
	char *file;
	dev_t dev_no;
	struct path f_path;

	event = bpf_map_lookup_elem(&execs, &pid);
	if (!event)
		return 0;

	__u8 *exists = bpf_map_lookup_elem(&security_bprm_hit_map, &pid);
	if (exists)
		return 0;

	__u8 hit = 1;
	if (bpf_map_update_elem(&security_bprm_hit_map, &pid, &hit, BPF_NOEXIST))
		return 0;

	struct file *s_file = BPF_CORE_READ(bprm, file);
	event->file_from_rootfs = is_from_rootfs(s_file);

	struct inode *inode = BPF_CORE_READ(s_file, f_inode);
	if (inode)
		event->fupper_layer = has_upper_layer(inode);

	if (paths) {
		f_path = BPF_CORE_READ(bprm, file, f_path);
		file = get_path_str(&f_path);
		bpf_probe_read_kernel_str(event->file, sizeof(event->file),
					  file);

		dev_no = BPF_CORE_READ(inode, i_sb, s_dev);
		event->dev_major = MAJOR(dev_no);
		event->dev_minor = MINOR(dev_no);
		event->inode = BPF_CORE_READ(inode, i_ino);
	}

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
