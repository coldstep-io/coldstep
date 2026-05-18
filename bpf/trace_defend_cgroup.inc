/*
 * Cgroup egress defend section of bpf/trace_defend_all.bpf.c.
 * IPv4 only (`cgroup/connect4`, `cgroup/sendmsg4`); IPv6 not supported.
 *
 * Maps in this section use bare names (no prefix): deny_events,
 * deny_reserve_failures, defend_cfg, allowed_ipv4, ignored_ipv4_lpm.
 * Policy helpers from defend_policy.inc are renamed to cg_* so the LSM
 * section can declare lsm_* equivalents in the same translation unit.
 *
 * The combined .bpf.c provides vmlinux/BPF helpers, LICENSE, shared
 * #defines (IPPROTO_*, AF_INET, COLDSTEP_*), the deny_event _Static_assert,
 * and dns_cache.h (allowed_domains + dns_cache) before including this file.
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
