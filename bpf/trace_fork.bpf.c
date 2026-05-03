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
	/* v0.3: session leader PID — identifies which login/CI session
	 * spawned the subtree. Read from child's task_struct→group_leader→
	 * signal_struct→leader_pid→numbers[0].nr at fork time. */
	__u32 child_sid;
	/* v0.3: PID namespace inode number — identifies container boundary.
	 * Different pidns_inum values mean different containers or namespaces. */
	__u32 child_pidns_inum;
};
_Static_assert(sizeof(struct fork_event) == 48,
	       "fork_event wire size must match forkEventWireSize=48 in agent_linux.go");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	/*
	 * 1<<22 = 4 MiB. fork_event is 48 bytes so this holds ~87,000 events —
	 * far more than any CI pipeline produces. Intentionally smaller than the
	 * 1<<24 (16 MiB) used by network ringbufs whose payloads are much larger.
	 */
	__uint(max_entries, 1 << 22);
} fork_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} fork_ringbuf_reserve_failures SEC(".maps");

static __always_inline void note_fork_ringbuf_reserve_failed(void)
{
	__u32 k = 0;
	__u32 *v = bpf_map_lookup_elem(&fork_ringbuf_reserve_failures, &k);

	if (!v)
		return;
	(*v)++;
}

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
	if (!ev) {
		note_fork_ringbuf_reserve_failed();
		return 0;
	}

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

	/* v0.3: session leader PID — best-effort via CO-RE. Zero on failure. */
	{
		pid_t sid = 0;
		struct pid *spid;

		spid = BPF_CORE_READ(child, group_leader, signal, pids[PIDTYPE_SID]);
		if (spid)
			sid = BPF_CORE_READ(spid, numbers[0].nr);
		ev->child_sid = (__u32)sid;
	}

	/* v0.3: PID namespace inode — container boundary detection. */
	ev->child_pidns_inum = (__u32)BPF_CORE_READ(child, nsproxy,
						     pid_ns_for_children,
						     ns.inum);

	bpf_ringbuf_submit(ev, 0);
	return 0;
}
