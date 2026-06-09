#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#ifndef EXE_PATH_MAX
#define EXE_PATH_MAX 256
#endif

/*
 * Sub-project C (ORDER 5 / Phase 5.1): kernel-truth executable identity.
 * comm + exe_path are attacker-controllable (a renamed/symlinked binary, a
 * forged argv[0]). exe_ino + exe_dev are read from the newly-installed
 * mm->exe_file->f_inode and uniquely identify the on-disk file independent of
 * its path: replacing the binary (new inode at the same path) changes exe_ino;
 * a rename keeps it. Userspace adds a best-effort content hash for tamper
 * detection (see telemetry.ExecEvent.ExeSHA256). 0/0 means the walk failed
 * (older kernel / no mm) — userspace treats that as "unknown identity".
 */
struct exec_event {
	__u32 tgid;
	__u32 tid;
	__u8 comm[16];
	__u8 exe_path[EXE_PATH_MAX];
	__u64 exe_ino;
	__u32 exe_dev;
	__u32 _pad;
};
_Static_assert(sizeof(struct exec_event) == 296,
	       "exec_event wire size must match execEventWireSize=296 in agent_linux.go");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} exec_ringbuf_reserve_failures SEC(".maps");

static __always_inline void note_exec_ringbuf_reserve_failed(void)
{
	__u32 k = 0;
	/* AUDIT(5a): null checked — `!v` returns before deref. */
	__u32 *v = bpf_map_lookup_elem(&exec_ringbuf_reserve_failures, &k);

	if (!v)
		return;
	(*v)++;
}

SEC("tp/sched/sched_process_exec")
int handle_sched_process_exec(void *ctx)
{
	struct trace_event_raw_sched_process_exec *e;
	struct exec_event *ev;
	__u64 pt;
	__u32 loc;
	__u32 off, len;
	void *src;

	e = (struct trace_event_raw_sched_process_exec *)ctx;
	/* AUDIT(5b): submit/discard paired — only exit between reserve and
	 * submit is the `!ev` early return (no slot held). Submit unconditional;
	 * probe_read_kernel_str return is intentionally ignored (ev->exe_path
	 * was memset to zero so failure leaves a zero-filled path). */
	ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
	if (!ev) {
		note_exec_ringbuf_reserve_failed();
		return 0;
	}

	pt = bpf_get_current_pid_tgid();
	ev->tgid = (__u32)(pt >> 32);
	ev->tid = (__u32)pt;
	bpf_get_current_comm(&ev->comm, sizeof(ev->comm));

	/*
	 * Kernel-truth identity: at sched_process_exec the new mm is installed,
	 * so mm->exe_file points at the binary that was just exec'd. Walk to its
	 * inode number + superblock device. CO-RE reads short-circuit to 0 on any
	 * missing field (e.g. kernel-thread exec with no mm), which userspace
	 * renders as "unknown".
	 *
	 * AUDIT(5e): task_struct.mm, mm_struct.exe_file, file.f_inode,
	 * inode.{i_ino,i_sb}, super_block.s_dev are all CO-RE-relocated and have
	 * been stable across 5.15-6.x.
	 */
	ev->exe_ino = 0;
	ev->exe_dev = 0;
	ev->_pad = 0;
	{
		struct task_struct *task = (struct task_struct *)bpf_get_current_task();

		if (task) {
			ev->exe_ino = BPF_CORE_READ(task, mm, exe_file, f_inode, i_ino);
			ev->exe_dev = BPF_CORE_READ(task, mm, exe_file, f_inode, i_sb, s_dev);
		}
	}

	__builtin_memset(&ev->exe_path, 0, sizeof(ev->exe_path));

	loc = e->__data_loc_filename;
	off = loc & 0xFFFF;
	len = (loc >> 16) & 0xFFFF;
	/*
	 * __data_loc packs the string as (length<<16 | offset) relative to the
	 * start of the trace record. Guard both: off must be non-zero (offset 0
	 * is the fixed record header, never the dynamic string section) and
	 * reasonably small (trace records are page-bounded).
	 *
	 * AUDIT(5c): pointer arithmetic bounded — `off` is verifier-guarded
	 * (0 < off < 4096) and `len` is clamped to EXE_PATH_MAX-1 below;
	 * bpf_probe_read_kernel_str performs the kernel-side bound on src.
	 * AUDIT(5f): return intentionally not checked — destination buffer was
	 * memset to zero above so failure yields an empty exe_path string.
	 */
	if (len > 0 && off > 0 && off < 4096) {
		src = (void *)((__u64)e + off); /* __data_loc: offset from trace record start */
		if (len >= EXE_PATH_MAX)
			len = EXE_PATH_MAX - 1;
		bpf_probe_read_kernel_str(ev->exe_path, len + 1, src);
	}

	bpf_ringbuf_submit(ev, 0);
	return 0;
}
