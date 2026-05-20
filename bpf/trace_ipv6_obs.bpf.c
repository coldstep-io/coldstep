/*
 * H7: Observe-only IPv6 egress hooks for detect mode.
 *
 * The defend BPF object (bpf/trace_defend_all.bpf.c) already carries
 * cgroup/connect6 and cgroup/sendmsg6 programs with per-CPU observe counters
 * (P0-1 Phase 1) and LPM-trie enforcement (P2-1 Phase 2). Those programs are
 * only loaded when `mode: defend`, so detect mode previously ran blind to
 * IPv6 egress.
 *
 * This translation unit provides a *standalone* observe-only object that the
 * agent loads in detect mode. Both hooks always return 1 (allow); they emit
 * a ringbuf record per non-loopback / non-link-local IPv6 connect / sendmsg
 * with (daddr, dport, pid, comm, hook). Userspace decodes the record into
 * telemetry.IPv6Event, bumps stats.IPv6EventCount, and the digest surfaces
 *   > ⚠️ IPv6 egress detected (not enforced) — N connection(s) observed
 * when count > 0.
 *
 * Loopback (::1) and link-local (fe80::/10) are skipped to avoid drowning the
 * ringbuf in mDNS / SLAAC / router solicitation traffic. The skip predicates
 * mirror cg_ipv6_is_loopback / cg_ipv6_is_link_local in trace_defend_cgroup.inc.
 *
 * In defend mode this object is NOT loaded — the defend object's own
 * cgroup/connect6 + cgroup/sendmsg6 hooks already attach there and would
 * conflict (cgroup attach is single-program by default).
 */
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

/*
 * Wire-format record decoded by readIPv6ObsRing in
 * internal/agent/agent_linux_ring_read.go. Field order and padding are
 * frozen — _Static_assert below pins the size at 44 bytes:
 *   daddr   [16]   offset 0
 *   dport   [2]    offset 16
 *   _pad0   [2]    offset 18
 *   pid     [4]    offset 20
 *   comm    [16]   offset 24
 *   hook    [1]    offset 40
 *   _pad1   [3]    offset 41 (trailing pad keeps the next struct __u32-aligned)
 */
struct ipv6_obs_event {
	__u8 daddr[16];
	__be16 dport;
	__u8 _pad0[2];
	__u32 pid;
	__u8 comm[16];
	__u8 hook; /* 0 = cgroup/connect6, 1 = cgroup/sendmsg6 */
	__u8 _pad1[3];
};
_Static_assert(sizeof(struct ipv6_obs_event) == 44,
	       "ipv6_obs_event wire size must match ipv6ObsEventWireSize=44 in agent_linux_ring_read.go");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	/*
	 * 1<<20 = 1 MiB. The record is 40 bytes so this holds ~26k events.
	 * Detect-mode CI runs rarely produce IPv6 egress at all, so a small
	 * ringbuf is sufficient; reserve failures are counted in the per-CPU
	 * map below.
	 */
	__uint(max_entries, 1 << 20);
} ipv6_obs_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} ipv6_obs_ringbuf_reserve_failures SEC(".maps");

static __always_inline void note_ipv6_obs_ringbuf_reserve_failed(void)
{
	__u32 k = 0;
	/* AUDIT(5a): null checked — `!v` returns before deref. */
	__u32 *v = bpf_map_lookup_elem(&ipv6_obs_ringbuf_reserve_failures, &k);

	if (!v)
		return;
	(*v)++;
}

/*
 * Same converter-load restriction as cg_copy_user_ip6_u32 in
 * trace_defend_cgroup.inc — issue four __u32 loads of ctx->user_ip6[i]
 * instead of a wider memcpy, because the cgroup-sockaddr verifier rejects
 * helper / memcpy reads of the converter-managed ctx pointer at non-zero
 * offsets.
 */
static __always_inline void ipv6_obs_copy_user_ip6_u32(struct bpf_sock_addr *ctx, __u32 dst[4])
{
	dst[0] = ctx->user_ip6[0];
	dst[1] = ctx->user_ip6[1];
	dst[2] = ctx->user_ip6[2];
	dst[3] = ctx->user_ip6[3];
}

/* ::1 is {0, 0, 0, htonl(1)} in network order across user_ip6[]. */
static __always_inline int ipv6_obs_is_loopback(struct bpf_sock_addr *ctx)
{
	return ctx->user_ip6[0] == 0 &&
	       ctx->user_ip6[1] == 0 &&
	       ctx->user_ip6[2] == 0 &&
	       ctx->user_ip6[3] == bpf_htonl(1);
}

/*
 * fe80::/10 — high 10 bits = 1111 1110 10xx, so the first __be32 (network
 * order) masked with htonl(0xffc00000) equals htonl(0xfe800000). Mirrors
 * cg_ipv6_is_link_local.
 */
static __always_inline int ipv6_obs_is_link_local(struct bpf_sock_addr *ctx)
{
	return (ctx->user_ip6[0] & bpf_htonl(0xffc00000)) == bpf_htonl(0xfe800000);
}

static __always_inline int ipv6_obs_emit(struct bpf_sock_addr *ctx, __u8 hook)
{
	struct ipv6_obs_event *ev;

	if (ipv6_obs_is_loopback(ctx))
		return 1;
	if (ipv6_obs_is_link_local(ctx))
		return 1;

	/* AUDIT(5b): submit/discard paired — only exit path between reserve and
	 * submit is the `!ev` early return (no slot held). Submit at end. */
	ev = bpf_ringbuf_reserve(&ipv6_obs_events, sizeof(*ev), 0);
	if (!ev) {
		note_ipv6_obs_ringbuf_reserve_failed();
		return 1;
	}

	__builtin_memset(ev, 0, sizeof(*ev));
	ipv6_obs_copy_user_ip6_u32(ctx, (__u32 *)&ev->daddr[0]);
	ev->dport = (__be16)ctx->user_port;
	ev->pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
	bpf_get_current_comm(&ev->comm, sizeof(ev->comm));
	ev->hook = hook;

	bpf_ringbuf_submit(ev, 0);
	return 1;
}

SEC("cgroup/connect6")
int ipv6_obs_connect6(struct bpf_sock_addr *ctx)
{
	return ipv6_obs_emit(ctx, 0);
}

SEC("cgroup/sendmsg6")
int ipv6_obs_sendmsg6(struct bpf_sock_addr *ctx)
{
	return ipv6_obs_emit(ctx, 1);
}
