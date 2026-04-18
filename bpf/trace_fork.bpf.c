#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct fork_event {
	__u32 parent_pid;
	__u32 child_pid;
	__u8 parent_comm[16];
	__u8 child_comm[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	/*
	 * 1<<22 = 4 MiB. fork_event is 52 bytes so this holds ~80,000 events —
	 * far more than any CI pipeline produces. Intentionally smaller than the
	 * 1<<24 (16 MiB) used by network ringbufs whose payloads are much larger.
	 */
	__uint(max_entries, 1 << 22);
} fork_events SEC(".maps");

/*
 * Use raw_tp + task_struct CO-RE instead of tp + trace_event_raw_sched_process_fork.
 * GitHub-hosted azure kernels ship vmlinux BTF where the fork trace record omits
 * inlined parent_comm/child_comm members, which breaks tp programs that read them.
 * Raw tracepoint args match TP_PROTO(struct task_struct *parent, struct task_struct *child).
 */
SEC("raw_tp/sched_process_fork")
int handle_sched_process_fork(struct bpf_raw_tracepoint_args *ctx)
{
	struct fork_event *ev;
	struct task_struct *parent = (void *)ctx->args[0];
	struct task_struct *child = (void *)ctx->args[1];
	pid_t ppid, cpid;

	ev = bpf_ringbuf_reserve(&fork_events, sizeof(*ev), 0);
	if (!ev)
		return 0;

	__builtin_memset(ev->parent_comm, 0, sizeof(ev->parent_comm));
	__builtin_memset(ev->child_comm, 0, sizeof(ev->child_comm));

	ppid = BPF_CORE_READ(parent, pid);
	cpid = BPF_CORE_READ(child, pid);
	ev->parent_pid = (__u32)ppid;
	ev->child_pid = (__u32)cpid;

	/* task_struct.comm is a fixed array; read through the kernel pointer. */
	if (bpf_probe_read_kernel_str(ev->parent_comm, sizeof(ev->parent_comm), &parent->comm))
		__builtin_memset(ev->parent_comm, 0, sizeof(ev->parent_comm));
	if (bpf_probe_read_kernel_str(ev->child_comm, sizeof(ev->child_comm), &child->comm))
		__builtin_memset(ev->child_comm, 0, sizeof(ev->child_comm));

	bpf_ringbuf_submit(ev, 0);
	return 0;
}
