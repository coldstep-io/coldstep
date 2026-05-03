/*
 * bpf() syscall audit observability.
 * Provides visibility into processes attempting to load programs, manipulate maps,
 * or attach hooks, as a BPF self-protection mechanism (Capability 7C).
 */
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "trace_connect_obs.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct bpf_audit_event {
	__u32 tgid;
	__u32 tid;
	int cmd;
	char comm[16];
};
_Static_assert(sizeof(struct bpf_audit_event) == 28,
	       "bpf_audit_event wire size mismatch");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 12); /* 4 KiB, low volume expected */
} bpf_audit_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} bpf_audit_reserve_failures SEC(".maps");

static __always_inline void note_bpf_audit_reserve_failed(void)
{
	__u32 k = 0;
	__u32 *v = bpf_map_lookup_elem(&bpf_audit_reserve_failures, &k);

	if (!v)
		return;
	(*v)++;
}

SEC("raw_tp/sys_enter")
int handle_raw_sys_enter_bpf(struct bpf_raw_tracepoint_args *ctx)
{
	struct pt_regs *regs = (void *)ctx->args[0];
	long id = (long)ctx->args[1];
	unsigned long cmd_ul = 0;

	if (!regs)
		return 0;

	if (id != (long)COLDSTEP_NR_BPF)
		return 0;

	if (ns_read_syscall_arg(regs, 0, &cmd_ul))
		return 0;

	struct bpf_audit_event *ev = bpf_ringbuf_reserve(&bpf_audit_events, sizeof(*ev), 0);
	if (!ev) {
		note_bpf_audit_reserve_failed();
		return 0;
	}

	__u64 pt = bpf_get_current_pid_tgid();
	ev->tgid = (__u32)(pt >> 32);
	ev->tid = (__u32)pt;
	ev->cmd = (int)cmd_ul;
	bpf_get_current_comm(&ev->comm, sizeof(ev->comm));

	bpf_ringbuf_submit(ev, 0);
	return 0;
}
