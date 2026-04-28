/*
 * BPF LSM enforcement for mode: enforce — IPv4 only (socket_connect, socket_sendmsg).
 * Provides robust enforcement by hooking into the Linux Security Module (LSM) framework.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "dns_cache.h"

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

#ifndef EPERM
#define EPERM 1
#endif

#define COLDSTEP_ENFORCE_KEY_MODE 0
#define COLDSTEP_ENFORCE_MODE_DETECT 0
#define COLDSTEP_ENFORCE_MODE_ENFORCE 1

#define COLDSTEP_PROTO_TCP 1
#define COLDSTEP_PROTO_UDP 2

#define COLDSTEP_DENY_REASON_DST_NOT_ALLOWLISTED 1

/* Packed wire format for userspace (see internal/agent decodeDenyEvent). */
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

_Static_assert(sizeof(struct deny_event) == 46, "deny_event wire size must match denyEventWireSize=46 in agent_linux.go");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} lsm_deny_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} lsm_deny_reserve_failures SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} lsm_enforce_cfg SEC(".maps");

struct ns_lpm4_key {
	__u32 prefixlen;
	__be32 addr;
} __attribute__((packed));

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 4096);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct ns_lpm4_key);
	__type(value, __u8);
} lsm_allowed_ipv4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 128);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct ns_lpm4_key);
	__type(value, __u8);
} lsm_ignored_ipv4_lpm SEC(".maps");

static __always_inline int enforcement_enabled(void)
{
	__u32 key = COLDSTEP_ENFORCE_KEY_MODE;
	__u32 *mode = bpf_map_lookup_elem(&lsm_enforce_cfg, &key);

	return mode && *mode == COLDSTEP_ENFORCE_MODE_ENFORCE;
}

static __always_inline int dst_is_allowlisted(__be32 addr)
{
	struct ns_lpm4_key k = {};

	/* Check IP/CIDR allowlist first (fast path) */
	k.prefixlen = 32;
	k.addr = addr;
	__u8 *ok = bpf_map_lookup_elem(&lsm_allowed_ipv4, &k);
	if (ok)
		return 1;

	/* 
	 * Check domain-based allowlist (late binding).
	 * Lookup IP in dns_cache map (populated by Go agent).
	 */
	char *domain = bpf_map_lookup_elem(&dns_cache, &addr);
	if (domain) {
		/* If IP matches a known domain, check if that domain is allowed. */
		__u8 *dom_ok = bpf_map_lookup_elem(&allowed_domains, domain);
		if (dom_ok)
			return 1;
	}

	return 0;
}

static __always_inline int dst_in_ignored(__be32 daddr)
{
	struct ns_lpm4_key k = {};

	k.prefixlen = 32;
	k.addr = daddr;
	__u8 *v = bpf_map_lookup_elem(&lsm_ignored_ipv4_lpm, &k);

	return v != 0;
}

static __always_inline void note_deny_ring_reserve_failed(void)
{
	__u32 k = 0;
	__u32 *v = bpf_map_lookup_elem(&lsm_deny_reserve_failures, &k);

	if (!v)
		return;
	__sync_fetch_and_add(v, 1);
}

static __always_inline void emit_deny_event_ipv4(__u8 protocol, const __u8 *dst4, __be16 dport, __u8 reason)
{
	struct deny_event *de = bpf_ringbuf_reserve(&lsm_deny_events, sizeof(*de), 0);

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
	de->af = AF_INET;
	de->_pad = 0;
	__builtin_memset(de->daddr, 0, sizeof(de->daddr));
	if (dst4)
		__builtin_memcpy(de->daddr, dst4, 4);
	__builtin_memcpy(de->dport, &dport, sizeof(de->dport));
	bpf_ringbuf_submit(de, 0);
}

/*
 * LSM hooks for enforcement return 0 to allow, or -EPERM to deny.
 */
SEC("lsm/socket_connect")
int BPF_PROG(lsm_socket_connect, struct socket *sock, struct sockaddr *address, int addrlen)
{
	if (!enforcement_enabled())
		return 0;
	if (!address)
		return 0;

	struct sockaddr_in *addr4 = (struct sockaddr_in *)address;
	short family;
	bpf_probe_read_kernel(&family, sizeof(family), &addr4->sin_family);

	if (family != AF_INET)
		return 0;

	struct sock *sk;
	bpf_probe_read_kernel(&sk, sizeof(sk), &sock->sk);
	if (!sk)
		return 0;

	short protocol;
	bpf_probe_read_kernel(&protocol, sizeof(protocol), &sk->sk_protocol);

	__u8 proto = (protocol == IPPROTO_UDP) ? COLDSTEP_PROTO_UDP : COLDSTEP_PROTO_TCP;

	__be32 daddr;
	__be16 dport;
	bpf_probe_read_kernel(&daddr, sizeof(daddr), &addr4->sin_addr.s_addr);
	bpf_probe_read_kernel(&dport, sizeof(dport), &addr4->sin_port);

	if (dst_in_ignored(daddr))
		return 0;
	if (dst_is_allowlisted(daddr))
		return 0;

	__u8 addr_bytes[4];
	__builtin_memcpy(addr_bytes, &daddr, sizeof(addr_bytes));
	emit_deny_event_ipv4(proto, addr_bytes, dport, COLDSTEP_DENY_REASON_DST_NOT_ALLOWLISTED);
	
	return -EPERM;
}

SEC("lsm/socket_sendmsg")
int BPF_PROG(lsm_socket_sendmsg, struct socket *sock, struct msghdr *msg, int size)
{
	if (!enforcement_enabled())
		return 0;
	
	if (!msg)
		return 0;

	struct sockaddr *address;
	bpf_probe_read_kernel(&address, sizeof(address), &msg->msg_name);
	if (!address)
		return 0;

	struct sockaddr_in *addr4 = (struct sockaddr_in *)address;
	short family;
	bpf_probe_read_kernel(&family, sizeof(family), &addr4->sin_family);

	if (family != AF_INET)
		return 0;

	struct sock *sk;
	bpf_probe_read_kernel(&sk, sizeof(sk), &sock->sk);
	if (!sk)
		return 0;

	short protocol;
	bpf_probe_read_kernel(&protocol, sizeof(protocol), &sk->sk_protocol);

	__u8 proto = (protocol == IPPROTO_UDP) ? COLDSTEP_PROTO_UDP : COLDSTEP_PROTO_TCP;

	__be32 daddr;
	__be16 dport;
	bpf_probe_read_kernel(&daddr, sizeof(daddr), &addr4->sin_addr.s_addr);
	bpf_probe_read_kernel(&dport, sizeof(dport), &addr4->sin_port);

	if (dst_in_ignored(daddr))
		return 0;
	if (dst_is_allowlisted(daddr))
		return 0;

	__u8 addr_bytes[4];
	__builtin_memcpy(addr_bytes, &daddr, sizeof(addr_bytes));
	emit_deny_event_ipv4(proto, addr_bytes, dport, COLDSTEP_DENY_REASON_DST_NOT_ALLOWLISTED);
	
	return -EPERM;
}
