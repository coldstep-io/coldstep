#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#ifndef EXE_PATH_MAX
#define EXE_PATH_MAX 256
#endif

struct exec_event {
	__u32 tgid;
	__u32 tid;
	__u8 comm[16];
	__u8 exe_path[EXE_PATH_MAX];
};
_Static_assert(sizeof(struct exec_event) == 280,
	       "exec_event wire size must match execEventWireSize=280 in agent_linux.go");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} exec_ringbuf_reserve_failures SEC(".maps");

static __always_inline void note_exec_ringbuf_reserve_failed(void)
{
	__u32 k = 0;
	__u32 *v = bpf_map_lookup_elem(&exec_ringbuf_reserve_failures, &k);

	if (!v)
		return;
	__sync_fetch_and_add(v, 1);
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
	ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
	if (!ev) {
		note_exec_ringbuf_reserve_failed();
		return 0;
	}

	pt = bpf_get_current_pid_tgid();
	ev->tgid = (__u32)(pt >> 32);
	ev->tid = (__u32)pt;
	bpf_get_current_comm(&ev->comm, sizeof(ev->comm));

	__builtin_memset(&ev->exe_path, 0, sizeof(ev->exe_path));

	loc = e->__data_loc_filename;
	off = loc & 0xFFFF;
	len = (loc >> 16) & 0xFFFF;
	/*
	 * __data_loc packs the string as (length<<16 | offset) relative to the
	 * start of the trace record. Guard both: off must be non-zero (offset 0
	 * is the fixed record header, never the dynamic string section) and
	 * reasonably small (trace records are page-bounded).
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
