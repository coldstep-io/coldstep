/*
 * Shared packed `deny_event` wire layout for both cgroup egress enforcement
 * (`bpf/trace_enforce.bpf.c`) and BPF LSM enforcement
 * (`bpf/trace_lsm_enforce.bpf.c`). Both objects emit identical 46-byte
 * records into their respective deny ringbufs (`deny_events`,
 * `lsm_deny_events`); userspace decodes both via `decodeDenyEvent` /
 * `denyEventWireSize=46` in `internal/agent/agent_linux.go`. Keeping a single
 * source of truth here prevents silent ABI drift between the two BPF objects
 * and the Go decoder.
 *
 * NOTE: Field additions or reorderings here are part of the wire ABI shared
 * with userspace — update `denyEventWireSize` and `decodeDenyEvent` in
 * `internal/agent/agent_linux.go` in the same change, and bump the
 * `_Static_assert` value below + at every include site.
 *
 * Layout (packed):
 *   tgid(4) + tid(4) + comm(16) + protocol(1) + reason(1) + af(1) + _pad(1)
 *   + daddr(16) + dport(2) = 46 bytes.
 */
#ifndef COLDSTEP_DENY_EVENT_H
#define COLDSTEP_DENY_EVENT_H

struct deny_event {
	__u32 tgid;
	__u32 tid;
	__u8 comm[16];
	__u8 protocol;
	__u8 reason;
	__u8 af;
	__u8 _pad;
	__u8 daddr[16];
	__u8 dport[2];
} __attribute__((packed));

_Static_assert(sizeof(struct deny_event) == 46,
	       "deny_event wire size must match denyEventWireSize=46 in agent_linux.go");

#endif /* COLDSTEP_DENY_EVENT_H */
