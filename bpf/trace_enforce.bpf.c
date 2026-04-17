/*
 * cgroup egress enforcement for mode: enforce — IPv4 only, hooks cgroup/connect4 and
 * cgroup/sendmsg4 (no IPv6). Intended for GitHub-hosted ephemeral Linux runners.
 * Loaded as a separate BPF collection from syscall observability programs.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

#define COLDSTEP_ENFORCE_KEY_MODE 0
#define COLDSTEP_ENFORCE_MODE_DETECT 0
#define COLDSTEP_ENFORCE_MODE_ENFORCE 1

#define COLDSTEP_PROTO_TCP 1
#define COLDSTEP_PROTO_UDP 2

#define COLDSTEP_DENY_REASON_DST_NOT_ALLOWLISTED 1

struct deny_event {
	__u32 tgid;
	__u32 tid;
	__u8 comm[16];
	__u8 protocol;
	__u8 reason;
	__u8 _pad[2];
	__u8 daddr[4];
	__u8 dport[2];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} deny_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} deny_reserve_failures SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} enforce_cfg SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __be32);
	__type(value, __u8);
} allowed_ipv4 SEC(".maps");

struct ns_lpm4_key {
	__u32 prefixlen;
	__be32 addr;
} __attribute__((packed));

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 128);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct ns_lpm4_key);
	__type(value, __u8);
} ignored_ipv4_lpm SEC(".maps");

static __always_inline int enforcement_enabled(void)
{
	__u32 key = COLDSTEP_ENFORCE_KEY_MODE;
	__u32 *mode = bpf_map_lookup_elem(&enforce_cfg, &key);

	return mode && *mode == COLDSTEP_ENFORCE_MODE_ENFORCE;
}

static __always_inline int dst_is_allowlisted(__be32 addr)
{
	__u8 *ok = bpf_map_lookup_elem(&allowed_ipv4, &addr);

	return ok != 0;
}

static __always_inline int dst_in_ignored(__be32 daddr)
{
	struct ns_lpm4_key k = {};

	k.prefixlen = 32;
	k.addr = daddr;
	__u8 *v = bpf_map_lookup_elem(&ignored_ipv4_lpm, &k);

	return v != 0;
}

static __always_inline __u8 protocol_from_sock_ctx(struct bpf_sock_addr *ctx)
{
	if (ctx->protocol == IPPROTO_UDP)
		return COLDSTEP_PROTO_UDP;
	return COLDSTEP_PROTO_TCP;
}

static __always_inline void note_deny_ring_reserve_failed(void)
{
	__u32 k = 0;
	__u32 *v = bpf_map_lookup_elem(&deny_reserve_failures, &k);

	if (!v)
		return;
	/* Shared map value may be updated concurrently; use atomic increment. */
	__sync_fetch_and_add(v, 1);
}

static __always_inline void emit_deny_event(__u8 protocol, __be32 daddr, __be16 dport, __u8 reason)
{
	struct deny_event *de = bpf_ringbuf_reserve(&deny_events, sizeof(*de), 0);

	if (!de) {
		note_deny_ring_reserve_failed();
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
	de->_pad[0] = 0;
	de->_pad[1] = 0;
	__builtin_memcpy(de->daddr, &daddr, sizeof(de->daddr));
	__builtin_memcpy(de->dport, &dport, sizeof(de->dport));
	bpf_ringbuf_submit(de, 0);
}

SEC("cgroup/connect4")
int enforce_connect4(struct bpf_sock_addr *ctx)
{
	__be32 daddr = (__be32)ctx->user_ip4;
	__be16 dport = (__be16)ctx->user_port;
	__u8 protocol = protocol_from_sock_ctx(ctx);

	if (!enforcement_enabled())
		return 1;
	if (dst_in_ignored(daddr))
		return 1;
	if (dst_is_allowlisted(daddr))
		return 1;

	emit_deny_event(protocol, daddr, dport,
			COLDSTEP_DENY_REASON_DST_NOT_ALLOWLISTED);
	return 0;
}

SEC("cgroup/sendmsg4")
int enforce_sendmsg4(struct bpf_sock_addr *ctx)
{
	__be32 daddr = (__be32)ctx->user_ip4;
	__be16 dport = (__be16)ctx->user_port;

	if (!enforcement_enabled())
		return 1;
	if (dst_in_ignored(daddr))
		return 1;
	if (dst_is_allowlisted(daddr))
		return 1;

	emit_deny_event(COLDSTEP_PROTO_UDP, daddr, dport,
			COLDSTEP_DENY_REASON_DST_NOT_ALLOWLISTED);
	return 0;
}
