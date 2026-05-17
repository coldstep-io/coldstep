/*
 * cgroup egress defend for mode: defend — IPv4 only (`cgroup/connect4`, `cgroup/sendmsg4`).
 * IPv6 is not supported. Loaded as a separate BPF collection from syscall observability programs.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "defend_lpm_key.h"
#include "dns_cache.h"
#include "deny_event.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

#ifndef AF_INET
#define AF_INET 2
#endif

#define COLDSTEP_DEFEND_KEY_MODE 0
#define COLDSTEP_DEFEND_MODE_DETECT 0
#define COLDSTEP_DEFEND_MODE_DEFEND 1

#define COLDSTEP_PROTO_TCP 1
#define COLDSTEP_PROTO_UDP 2

#define COLDSTEP_DENY_REASON_DST_NOT_ALLOWLISTED 1

_Static_assert(sizeof(struct deny_event) == 46,
	       "deny_event wire size must match denyEventWireSize=46 in agent_linux.go");

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

static __always_inline __u8 protocol_from_sock_ctx(struct bpf_sock_addr *ctx)
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
	__u8 protocol = protocol_from_sock_ctx(ctx);
	__u8 addr4[4];

	if (!defense_enabled())
		return 1;
	if (dst_in_ignored(daddr))
		return 1;
	if (dst_is_allowlisted(daddr))
		return 1;

	__builtin_memcpy(addr4, &daddr, sizeof(addr4));
	emit_deny_event_ipv4(protocol, addr4, dport, COLDSTEP_DENY_REASON_DST_NOT_ALLOWLISTED);
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
