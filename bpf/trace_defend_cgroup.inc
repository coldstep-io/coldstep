/*
 * Cgroup egress defend section of bpf/trace_defend_all.bpf.c.
 *
 * IPv4 paths (`cgroup/connect4`, `cgroup/sendmsg4`) and IPv6 paths
 * (`cgroup/connect6`, `cgroup/sendmsg6`) both carry policy-based deny
 * logic. P2-1 Phase 2 added the IPv6 LPM allowlist (`allowed_ipv6`) and
 * deny emission; ::1 (loopback) and fe80::/10 (link-local) bypass enforcement
 * and the observe-only counters (`ipv6_connect_observed`,
 * `ipv6_sendmsg_observed`) still bump for visibility.
 *
 * Maps in this section use bare names (no prefix): deny_events,
 * deny_reserve_failures, defend_cfg, allowed_ipv4, ignored_ipv4_lpm,
 * allowed_ipv6, ipv6_connect_observed, ipv6_sendmsg_observed.
 * Policy helpers from defend_policy.inc are renamed to cg_* so the LSM
 * section can declare lsm_* equivalents in the same translation unit.
 *
 * The combined .bpf.c provides vmlinux/BPF helpers, LICENSE, shared
 * #defines (IPPROTO_*, AF_INET, AF_INET6, COLDSTEP_*), the deny_event
 * _Static_assert, and dns_cache.h (allowed_domains + dns_cache) before
 * including this file.
 */

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} deny_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} deny_reserve_failures SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} defend_cfg SEC(".maps");

/*
 * PR-G (Theme G): LPM trie allowlist + ignored trie; sizes locked with abi_test.go.
 */
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 4096);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct ns_lpm4_key);
	__type(value, __u8);
} allowed_ipv4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 128);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct ns_lpm4_key);
	__type(value, __u8);
} ignored_ipv4_lpm SEC(".maps");

/*
 * P2-1 Phase 2: IPv6 defend allowlist. AAAA-resolved domain entries plus
 * implicit ::1/128 (loopback) and fe80::/10 (link-local) bypass live here.
 * Sized identically to allowed_ipv4 (4096) so the abi_test pair stays
 * symmetric; userspace bounds inserts by policy.MaxAllowedDefendIPv6Keys.
 */
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 4096);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct lpm_v6_key);
	__type(value, __u8);
} allowed_ipv6 SEC(".maps");

/*
 * P0-1 Phase 1: IPv6 egress observe-only counters. cgroup/connect6 and
 * cgroup/sendmsg6 hooks below bump these on any non-loopback IPv6
 * destination but never deny — surfaces the silent IPv6 bypass gap
 * (IPv4-only enforcement) in the digest as a warning. Per-cpu uint32
 * to avoid cache-line contention; userspace sums across CPUs.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} ipv6_connect_observed SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} ipv6_sendmsg_observed SEC(".maps");

#define defense_enabled cg_defense_enabled
#define dst_is_allowlisted cg_dst_is_allowlisted
#define dst_in_ignored cg_dst_in_ignored
#define note_deny_ring_reserve_failed cg_note_deny_ring_reserve_failed
#define emit_deny_event_ipv4 cg_emit_deny_event_ipv4
#define CS_DEF_RB_DENY deny_events
#define CS_DEF_PC_DENY_FAIL deny_reserve_failures
#define CS_DEF_ARR_DEFEND_CFG defend_cfg
#define CS_DEF_TRIE_ALLOWED allowed_ipv4
#define CS_DEF_TRIE_IGNORED ignored_ipv4_lpm
#include "defend_policy.inc"
#undef CS_DEF_RB_DENY
#undef CS_DEF_PC_DENY_FAIL
#undef CS_DEF_ARR_DEFEND_CFG
#undef CS_DEF_TRIE_ALLOWED
#undef CS_DEF_TRIE_IGNORED
#undef defense_enabled
#undef dst_is_allowlisted
#undef dst_in_ignored
#undef note_deny_ring_reserve_failed
#undef emit_deny_event_ipv4

static __always_inline __u8 cg_protocol_from_sock_ctx(struct bpf_sock_addr *ctx)
{
	if (ctx->protocol == IPPROTO_UDP)
		return COLDSTEP_PROTO_UDP;
	return COLDSTEP_PROTO_TCP;
}

/*
 * Successful outcome returns 1 (allow syscall); deny returns 0 — cgroup/connect4 convention.
 */
static __always_inline int defend_cgroup_sock_addr_ipv4(struct bpf_sock_addr *ctx)
{
	__be32 daddr = (__be32)ctx->user_ip4;
	__be16 dport = (__be16)ctx->user_port;
	__u8 protocol = cg_protocol_from_sock_ctx(ctx);
	__u8 addr4[4];

	if (!cg_defense_enabled())
		return 1;
	if (cg_dst_in_ignored(daddr))
		return 1;
	if (cg_dst_is_allowlisted(daddr))
		return 1;

	__builtin_memcpy(addr4, &daddr, sizeof(addr4));
	cg_emit_deny_event_ipv4(protocol, addr4, dport, COLDSTEP_DENY_REASON_DST_NOT_ALLOWLISTED);
	return 0;
}

SEC("cgroup/connect4")
int defend_connect4(struct bpf_sock_addr *ctx)
{
	return defend_cgroup_sock_addr_ipv4(ctx);
}

SEC("cgroup/sendmsg4")
int defend_sendmsg4(struct bpf_sock_addr *ctx)
{
	return defend_cgroup_sock_addr_ipv4(ctx);
}

/*
 * IPv6 loopback (::1) check: user_ip6 is __be32[4] in network byte order;
 * ::1 is {0,0,0,htonl(1)}. Skip loopback so test runners' localhost IPv6
 * traffic doesn't dominate the counter, and so loopback always bypasses
 * Phase 2 enforcement.
 */
static __always_inline int cg_ipv6_is_loopback(struct bpf_sock_addr *ctx)
{
	return ctx->user_ip6[0] == 0 &&
	       ctx->user_ip6[1] == 0 &&
	       ctx->user_ip6[2] == 0 &&
	       ctx->user_ip6[3] == bpf_htonl(1);
}

/*
 * :: (unspecified) check. The kernel rewrites an all-zero connect/sendmsg
 * destination to loopback, but only after this hook runs — see
 * coldstep_ipv6_is_unspecified in coldstep_pure.h. Twin of the 0.0.0.0 bypass
 * on the IPv4 path (cg_dst_in_ignored -> coldstep_ipv4_is_unspecified).
 */
static __always_inline int cg_ipv6_is_unspecified(struct bpf_sock_addr *ctx)
{
	/*
	 * Four direct converter loads rather than coldstep_ipv6_is_unspecified on
	 * a copied array — same constraint cg_copy_user_ip6_u32 documents, and it
	 * keeps this helper next to its cg_ipv6_is_loopback / _link_local siblings
	 * (which is above cg_copy_user_ip6_u32's definition).
	 */
	return ctx->user_ip6[0] == 0 &&
	       ctx->user_ip6[1] == 0 &&
	       ctx->user_ip6[2] == 0 &&
	       ctx->user_ip6[3] == 0;
}

/*
 * IPv6 link-local (fe80::/10) check: user_ip6[0] is the first __be32 of
 * the IPv6 address in network byte order, so the high-order bytes are at
 * the low memory addresses. fe80::/10 = first 10 bits 1111 1110 10xx, i.e.
 * the high 16 bits are 0xfe80..0xfebf — equivalently network-order
 * (user_ip6[0] & htonl(0xffc00000)) == htonl(0xfe800000). Always-bypass
 * for these so router solicitations / mDNS / SLAAC discovery don't get
 * blocked.
 */
static __always_inline int cg_ipv6_is_link_local(struct bpf_sock_addr *ctx)
{
	return (ctx->user_ip6[0] & bpf_htonl(0xffc00000)) == bpf_htonl(0xfe800000);
}

/*
 * IPv4-mapped IPv6 (::ffff:0:0/96): the high 80 bits are zero and bytes
 * 10-11 are 0xffff, so user_ip6[0]==0, user_ip6[1]==0, user_ip6[2]==
 * htonl(0x0000ffff). The embedded IPv4 (user_ip6[3], already network byte
 * order) is the real wire destination — a dual-stack socket connecting to
 * an allowlisted IPv4 via ::ffff:a.b.c.d must be gated by the IPv4 allowlist,
 * not the AAAA-only allowed_ipv6 trie (which would falsely deny it).
 */
static __always_inline int cg_ipv6_is_v4mapped(struct bpf_sock_addr *ctx)
{
	return ctx->user_ip6[0] == 0 &&
	       ctx->user_ip6[1] == 0 &&
	       ctx->user_ip6[2] == bpf_htonl(0x0000ffff);
}

static __always_inline void cg_bump_percpu_u32(void *map)
{
	__u32 key = 0;
	/* AUDIT(5a): null checked — only used inside `if (val)`. */
	__u32 *val = bpf_map_lookup_elem(map, &key);
	if (val)
		__sync_fetch_and_add(val, 1);
}

/*
 * Copy the 16-byte IPv6 destination from ctx->user_ip6 into a __u32[4]
 * aligned destination. The cgroup/connect|sendmsg6 verifier rewrites
 * each `ctx->user_ip6[i]` access into a 4-byte converter load against
 * the internal sockaddr fields. A wider read (e.g. `__builtin_memcpy
 * (dst, &ctx->user_ip6[0], 16)`) is rejected with "dereference of
 * modified ctx ptr R2 off=8 disallowed" because the verifier won't let
 * helpers / memcpy receive the converter-managed ctx pointer at a
 * non-zero offset. Issuing four direct __u32 loads stays inside the
 * allowed access pattern.
 */
static __always_inline void cg_copy_user_ip6_u32(struct bpf_sock_addr *ctx, __u32 dst[4])
{
	dst[0] = ctx->user_ip6[0];
	dst[1] = ctx->user_ip6[1];
	dst[2] = ctx->user_ip6[2];
	dst[3] = ctx->user_ip6[3];
}

/*
 * IPv6 allowlist LPM lookup. user_ip6 is __be32[4] (network order); the
 * LPM trie key copies those 16 bytes verbatim into struct lpm_v6_key.addr.
 * Prefixlen is set to /128 for the lookup itself; the trie matches
 * longest-prefix against shorter inserted prefixes (e.g. /48 from AAAA
 * resolution).
 */
static __always_inline int cg_ipv6_is_allowlisted(struct bpf_sock_addr *ctx)
{
	struct lpm_v6_key k = {};

	k.prefixlen = 128;
	cg_copy_user_ip6_u32(ctx, (__u32 *)&k.addr[0]);
	/* AUDIT(5a): null checked — only used inside `if (ok)`. */
	__u8 *ok = bpf_map_lookup_elem(&allowed_ipv6, &k);
	return ok != 0;
}

/*
 * Emit an IPv6 deny event into the shared deny_events ringbuf. The
 * `deny_event` wire layout has a 16-byte daddr field that already
 * accommodates an IPv6 address; userspace inspects `af` to decide how to
 * render it. Mirrors emit_deny_event_ipv4 from defend_policy.inc but
 * sets af=AF_INET6 and writes all 16 bytes.
 */
static __always_inline void cg_emit_deny_event_ipv6(__u8 protocol, struct bpf_sock_addr *ctx,
						    __be16 dport, __u8 reason)
{
	/* AUDIT(5b): submit/discard paired — only exit path between reserve and
	 * submit is the `!de` early return (no slot held). Submit at end. */
	struct deny_event *de = bpf_ringbuf_reserve(&deny_events, sizeof(*de), 0);

	if (!de) {
		cg_note_deny_ring_reserve_failed();
		return;
	}
	{
		__u64 pt = bpf_get_current_pid_tgid();

		de->tgid = (__u32)(pt >> 32);
		de->tid = (__u32)pt;
	}
	bpf_get_current_comm(&de->comm, sizeof(de->comm));
	de->protocol = protocol;
	de->reason = reason;
	de->af = AF_INET6;
	de->_pad = 0;
	/*
	 * Same converter-load restriction as cg_copy_user_ip6_u32 — avoid
	 * passing &ctx->user_ip6[0] to memcpy and instead emit four 4-byte
	 * stores into the ringbuf record. de->daddr starts at offset 28
	 * (4+4+16+1+1+1+1) inside the packed deny_event, which is __u32-
	 * aligned so the casts are sound.
	 */
	cg_copy_user_ip6_u32(ctx, (__u32 *)&de->daddr[0]);
	__builtin_memcpy(de->dport, &dport, sizeof(de->dport));
	bpf_ringbuf_submit(de, 0);
}

/*
 * P2-1 Phase 2: IPv6 enforcement. ::1 (loopback) and fe80::/10
 * (link-local) always allow; non-loopback destinations still bump the
 * observe counter for visibility regardless of defend state. In defend
 * mode, look up against the allowed_ipv6 LPM trie; non-matches emit a
 * deny event and return 0 (EPERM-equivalent for cgroup sockaddr).
 */
static __always_inline int defend_cgroup_sock_addr_ipv6(struct bpf_sock_addr *ctx,
							void *observe_map)
{
	__be16 dport = (__be16)ctx->user_port;
	__u8 protocol = cg_protocol_from_sock_ctx(ctx);

	if (cg_ipv6_is_loopback(ctx))
		return 1;
	if (cg_ipv6_is_unspecified(ctx))
		return 1;
	if (cg_ipv6_is_link_local(ctx))
		return 1;

	/*
	 * IPv4-mapped IPv6: gate the embedded IPv4 against the IPv4 allowlist /
	 * ignored trie and emit an IPv4-family deny on miss. The wire traffic is
	 * IPv4, so this keeps a dual-stack socket to an allowlisted IPv4 from
	 * being falsely blocked while still denying non-allowlisted destinations.
	 * Mirrors defend_cgroup_sock_addr_ipv4; does not bump the IPv6 observe
	 * counter (the destination is not genuine IPv6 egress).
	 */
	if (cg_ipv6_is_v4mapped(ctx)) {
		__be32 v4 = ctx->user_ip6[3]; /* network byte order */
		__u8 addr4[4];

		if (!cg_defense_enabled())
			return 1;
		if (cg_dst_in_ignored(v4))
			return 1;
		if (cg_dst_is_allowlisted(v4))
			return 1;
		__builtin_memcpy(addr4, &v4, sizeof(addr4));
		cg_emit_deny_event_ipv4(protocol, addr4, dport, COLDSTEP_DENY_REASON_DST_NOT_ALLOWLISTED);
		return 0;
	}

	cg_bump_percpu_u32(observe_map);

	if (!cg_defense_enabled())
		return 1;
	if (cg_ipv6_is_allowlisted(ctx))
		return 1;

	cg_emit_deny_event_ipv6(protocol, ctx, dport, COLDSTEP_DENY_REASON_DST_NOT_ALLOWLISTED);
	return 0;
}

SEC("cgroup/connect6")
int defend_cgroup_connect6(struct bpf_sock_addr *ctx)
{
	return defend_cgroup_sock_addr_ipv6(ctx, &ipv6_connect_observed);
}

SEC("cgroup/sendmsg6")
int defend_cgroup_sendmsg6(struct bpf_sock_addr *ctx)
{
	return defend_cgroup_sock_addr_ipv6(ctx, &ipv6_sendmsg_observed);
}
