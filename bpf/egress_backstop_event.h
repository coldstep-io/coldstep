/*
 * Shared packed `egress_backstop_event` wire layout for the cgroup_skb egress
 * backstop (sub-project A). Emitted into the `skb_backstop_events` ringbuf by
 * bpf/trace_defend_skb.inc; decoded by decodeEgressBackstopEvent /
 * egressBackstopEventWireSize=56 in internal/agent.
 *
 * Field additions/reorderings are wire ABI shared with userspace — update
 * egressBackstopEventWireSize + decodeEgressBackstopEvent and bump the
 * _Static_assert in the same change.
 *
 * Layout (alignment-of-8 from the leading __u64):
 *   ts(8) + pid(4) + comm(16) + af(1) + ipproto(1) + _pad(2) + daddr(16)
 *   + dport(2) + _pad2(6) = 56.
 */
#ifndef COLDSTEP_EGRESS_BACKSTOP_EVENT_H
#define COLDSTEP_EGRESS_BACKSTOP_EVENT_H

struct egress_backstop_event {
	__u64 timestamp_ns;
	__u32 pid;
	__u8  comm[16];
	__u8  af;       /* AF_INET / AF_INET6 */
	__u8  ipproto;  /* raw IP-header protocol byte (6=TCP,17=UDP,...) */
	__u8  _pad[2];
	__u8  daddr[16];
	__u8  dport[2]; /* network byte order */
	__u8  _pad2[6];
};

_Static_assert(sizeof(struct egress_backstop_event) == 56,
	       "egress_backstop_event wire size must match egressBackstopEventWireSize=56 in agent_linux_decode.go");

#endif /* COLDSTEP_EGRESS_BACKSTOP_EVENT_H */
