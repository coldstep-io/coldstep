/*
 * BPF LSM enforcement for mode: enforce — IPv4 only (socket_connect, socket_sendmsg).
 * Provides robust enforcement by hooking into the Linux Security Module (LSM) framework.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "trace_connect_obs.h"
#include "enforce_lpm_key.h"
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

#ifndef EPERM
#define EPERM 1
#endif

#define COLDSTEP_ENFORCE_KEY_MODE 0
#define COLDSTEP_ENFORCE_MODE_DETECT 0
#define COLDSTEP_ENFORCE_MODE_ENFORCE 1

#define COLDSTEP_PROTO_TCP 1
#define COLDSTEP_PROTO_UDP 2

#define COLDSTEP_DENY_REASON_DST_NOT_ALLOWLISTED 1

_Static_assert(sizeof(struct deny_event) == 46,
	       "deny_event wire size must match denyEventWireSize=46 in agent_linux.go");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} lsm_deny_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
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

#define CS_EF_RB_DENY lsm_deny_events
#define CS_EF_PC_DENY_FAIL lsm_deny_reserve_failures
#define CS_EF_ARR_ENFORCE_CFG lsm_enforce_cfg
#define CS_EF_TRIE_ALLOWED lsm_allowed_ipv4
#define CS_EF_TRIE_IGNORED lsm_ignored_ipv4_lpm
#include "enforce_policy.inc"
#undef CS_EF_RB_DENY
#undef CS_EF_PC_DENY_FAIL
#undef CS_EF_ARR_ENFORCE_CFG
#undef CS_EF_TRIE_ALLOWED
#undef CS_EF_TRIE_IGNORED

/*
 * LSM hooks return 0 to allow, -EPERM to deny.
 */
SEC("lsm/socket_connect")
int BPF_PROG(lsm_socket_connect, struct socket *sock, struct sockaddr *address, int addrlen)
{
	if (!enforcement_enabled())
		return 0;
	if (!address)
		return 0;
	/* Guard sockaddr_in shape — short addrlen avoids garbage family/addr reads. */
	if (addrlen < (int)sizeof(struct sockaddr_in))
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

	/*
	 * H-01 / M-04 (BPF Deep Audit, 2026-05-01): Connected TCP/UDP commonly uses
	 * sendmsg with NULL msg_name — derive IPv4 peer from sock_common when absent.
	 * When msg_name is set, read_ipv4_sockaddr(msg_name) honors short namelen.
	 * Cgroup sendmsg4 (separate object) complements this path on kernels with cgroup BPF.
	 */

	struct sock *sk = NULL;
	bpf_probe_read_kernel(&sk, sizeof(sk), &sock->sk);
	if (!sk)
		return 0;

	short protocol;
	bpf_probe_read_kernel(&protocol, sizeof(protocol), &sk->sk_protocol);
	__u8 proto = (protocol == IPPROTO_UDP) ? COLDSTEP_PROTO_UDP : COLDSTEP_PROTO_TCP;

	struct sockaddr *address = NULL;
	int namelen = 0;
	bpf_probe_read_kernel(&address, sizeof(address), &msg->msg_name);
	bpf_probe_read_kernel(&namelen, sizeof(namelen), &msg->msg_namelen);

	__be32 daddr = 0;
	__be16 dport = 0;

	if (address && namelen >= (int)sizeof(struct sockaddr_in)) {
		if (read_ipv4_sockaddr((unsigned long)address, &dport, &daddr))
			return 0;
	} else {
		__u16 sk_family = 0;
		bpf_probe_read_kernel(&sk_family, sizeof(sk_family),
				      &sk->__sk_common.skc_family);
		if (sk_family != AF_INET)
			return 0;

		bpf_probe_read_kernel(&daddr, sizeof(daddr),
				      &sk->__sk_common.skc_daddr);
		bpf_probe_read_kernel(&dport, sizeof(dport),
				      &sk->__sk_common.skc_dport);

		if (daddr == 0)
			return 0;
	}

	if (dst_in_ignored(daddr))
		return 0;
	if (dst_is_allowlisted(daddr))
		return 0;

	__u8 addr_bytes[4];
	__builtin_memcpy(addr_bytes, &daddr, sizeof(addr_bytes));
	emit_deny_event_ipv4(proto, addr_bytes, dport, COLDSTEP_DENY_REASON_DST_NOT_ALLOWLISTED);

	return -EPERM;
}
