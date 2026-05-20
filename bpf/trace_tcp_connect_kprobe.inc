/*
 * P3-2: paired kprobe/kretprobe on tcp_v4_connect.
 *
 * The raw_tp/sys_enter arm in trace_tcp_obs.inc emits a connect_event at
 * syscall entry — before the kernel decides whether the destination is
 * reachable. That made timed-out / refused / unreachable connections
 * indistinguishable from established ones in the JSONL stream. This pair
 * captures tcp_v4_connect's return value (0 on success, negative errno
 * otherwise) and emits a supplementary connect_result_event into the
 * connect_events ringbuf, correlated by pid_tgid.
 *
 * tcp_v4_connect runs synchronously in the caller's task context (no
 * scheduling between entry and return on the IPv4 TCP path), so an
 * LRU_HASH map keyed by bpf_get_current_pid_tgid() is a sufficient
 * correlation primitive — no cross-CPU concerns. The map bounds the
 * in-flight set at 4096 entries; in practice the kernel rarely has more
 * than a few concurrent tcp_v4_connect invocations per CPU. LRU_HASH (vs
 * plain HASH) is chosen so that orphaned entries from dropped or missed
 * kretprobes (e.g. when an attach point is bypassed by a fault path) are
 * automatically evicted by the kernel rather than filling the table and
 * silently blocking every subsequent BPF_NOEXIST insert. If userspace
 * blows past the bound we silently drop the result event — the entry
 * connect_event is still recorded, just without a paired result.
 *
 * Wire compatibility: connect_result_event reuses the connect_events
 * ringbuf (already drained by readConnectRing) but is distinguished from
 * connect_event by a 4-byte magic prefix at offset 0 — Linux PIDs are
 * always < PID_MAX_LIMIT (4194304 on 64-bit), so 0xC0EE0001 cannot collide
 * with a real connect_event's leading tgid field. Same pattern the canary
 * event uses (CANARY_MAGIC = 0xCA1A1210).
 */
#ifndef TRACE_TCP_CONNECT_KPROBE_INC
#define TRACE_TCP_CONNECT_KPROBE_INC

#define CONNECT_RESULT_MAGIC 0xC0EE0001u

struct connect_result_event {
	__u32 magic;       /* 0xC0EE0001 */
	__s32 result;      /* tcp_v4_connect return: 0 ok, negative errno */
	__u32 tgid;
	__u32 tid;
	__u8 comm[16];
};
_Static_assert(sizeof(struct connect_result_event) == 32,
	       "connect_result_event wire size must match connectResultEventWireSize=32 in agent_linux.go");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, __u8);
} tcp_v4_connect_inflight SEC(".maps");

SEC("kprobe/tcp_v4_connect")
int kprobe_tcp_v4_connect(struct pt_regs *ctx)
{
	__u64 pt = bpf_get_current_pid_tgid();
	__u8 v = 1;
	/* BPF_NOEXIST avoids stomping a prior in-flight entry from a nested
	 * call on the same task, which would mismatch the eventual return. */
	bpf_map_update_elem(&tcp_v4_connect_inflight, &pt, &v, BPF_NOEXIST);
	return 0;
}

SEC("kretprobe/tcp_v4_connect")
int kretprobe_tcp_v4_connect(struct pt_regs *ctx)
{
	__u64 pt = bpf_get_current_pid_tgid();
	__u8 *seen = bpf_map_lookup_elem(&tcp_v4_connect_inflight, &pt);

	if (!seen)
		return 0;
	bpf_map_delete_elem(&tcp_v4_connect_inflight, &pt);

	struct connect_result_event *ev =
		bpf_ringbuf_reserve(&connect_events, sizeof(*ev), 0);
	if (!ev) {
		note_connect_ringbuf_reserve_failed();
		return 0;
	}
	ev->magic = CONNECT_RESULT_MAGIC;
	ev->result = (__s32)PT_REGS_RC(ctx);
	ev->tgid = (__u32)(pt >> 32);
	ev->tid = (__u32)pt;
	bpf_get_current_comm(&ev->comm, sizeof(ev->comm));
	bpf_ringbuf_submit(ev, 0);
	return 0;
}

#endif /* TRACE_TCP_CONNECT_KPROBE_INC */
