/*
 * LSM defend section of bpf/trace_defend_all.bpf.c.
 * IPv4 only (`lsm/socket_connect`, `lsm/socket_sendmsg`, `lsm/socket_sendpage`).
 *
 * Maps in this section carry the lsm_ prefix to coexist with the cgroup
 * section's bare-named maps in the same translation unit. Policy helpers
 * from defend_policy.inc are renamed to lsm_*.
 *
 * `lsm/socket_sendpage` closes the kernel 5.15 sendfile(2)/splice(2) gap:
 * those syscalls reach the socket via sock_sendpage()/security_socket_sendpage()
 * rather than sendmsg(), so cgroup/sendmsg4 and lsm/socket_sendmsg never see
 * them. On kernel 6.8+ the sendmsg path covers sendfile/splice via the
 * MSG_SPLICE_PAGES flag, but the sendpage LSM hook is harmless there
 * (the kernel simply never invokes the sendpage security_*).
 *
 * The combined .bpf.c provides vmlinux/BPF helpers, LICENSE, shared
 * #defines (IPPROTO_*, AF_INET, EPERM, COLDSTEP_*), the deny_event
 * _Static_assert, trace_connect_obs.h (read_ipv4_sockaddr for the sendmsg
 * explicit-destination path), and dns_cache.h before including this file.
 */

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
} lsm_defend_cfg SEC(".maps");

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

/*
 * Sendfile/splice gap counter. Bumped by defend_lsm_socket_sendpage on
 * every sock_sendpage() call (IPv4 or non-IPv4) so userspace can see
 * how much sendfile/splice traffic the cgroup/sendmsg4 + lsm/socket_sendmsg
 * pair missed before the sendpage hook was added. Per-cpu uint32 to avoid
 * cache-line contention; userspace sums across CPUs.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} sendpage_observed SEC(".maps");

#define defense_enabled lsm_defense_enabled
#define dst_is_allowlisted lsm_dst_is_allowlisted
#define dst_in_ignored lsm_dst_in_ignored
#define note_deny_ring_reserve_failed lsm_note_deny_ring_reserve_failed
#define emit_deny_event_ipv4 lsm_emit_deny_event_ipv4
#define CS_DEF_RB_DENY lsm_deny_events
#define CS_DEF_PC_DENY_FAIL lsm_deny_reserve_failures
#define CS_DEF_ARR_DEFEND_CFG lsm_defend_cfg
#define CS_DEF_TRIE_ALLOWED lsm_allowed_ipv4
#define CS_DEF_TRIE_IGNORED lsm_ignored_ipv4_lpm
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

/*
 * LSM hooks return 0 to allow, -EPERM to deny.
 */
SEC("lsm/socket_connect")
int BPF_PROG(lsm_socket_connect, struct socket *sock, struct sockaddr *address, int addrlen)
{
	if (!lsm_defense_enabled())
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

	if (lsm_dst_in_ignored(daddr))
		return 0;
	if (lsm_dst_is_allowlisted(daddr))
		return 0;

	__u8 addr_bytes[4];
	__builtin_memcpy(addr_bytes, &daddr, sizeof(addr_bytes));
	lsm_emit_deny_event_ipv4(proto, addr_bytes, dport, COLDSTEP_DENY_REASON_DST_NOT_ALLOWLISTED);

	return -EPERM;
}

static __always_inline void lsm_bump_percpu_u32(void *map)
{
	__u32 key = 0;
	__u32 *val = bpf_map_lookup_elem(map, &key);
	if (val)
		__sync_fetch_and_add(val, 1);
}

SEC("lsm/socket_sendmsg")
int BPF_PROG(lsm_socket_sendmsg, struct socket *sock, struct msghdr *msg, int size)
{
	if (!lsm_defense_enabled())
		return 0;

	if (!msg)
		return 0;

	/*
	 * H-01 / M-04 (BPF Deep Audit, 2026-05-01): Connected TCP/UDP commonly uses
	 * sendmsg with NULL msg_name — derive IPv4 peer from sock_common when absent.
	 * When msg_name is set, read_ipv4_sockaddr(msg_name) honors short namelen.
	 * Cgroup sendmsg4 (combined into the same defend object) complements this
	 * path on kernels with cgroup BPF.
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

	if (lsm_dst_in_ignored(daddr))
		return 0;
	if (lsm_dst_is_allowlisted(daddr))
		return 0;

	__u8 addr_bytes[4];
	__builtin_memcpy(addr_bytes, &daddr, sizeof(addr_bytes));
	lsm_emit_deny_event_ipv4(proto, addr_bytes, dport, COLDSTEP_DENY_REASON_DST_NOT_ALLOWLISTED);

	return -EPERM;
}

/*
 * lsm/socket_sendpage closes the kernel-5.15 sendfile(2)/splice(2) egress gap.
 * Those syscalls go through sock_sendpage() → security_socket_sendpage()
 * without ever calling sendmsg, so cgroup/sendmsg4 and lsm/socket_sendmsg
 * cannot gate them. On kernel 6.8+ the sendmsg path covers sendfile/splice
 * via MSG_SPLICE_PAGES and this hook is simply never invoked — harmless.
 *
 * Decision logic mirrors lsm_socket_sendmsg's connected-socket fallback:
 * sendpage has no msghdr / sockaddr argument, so the destination always
 * comes from the connected sock's skc_daddr/skc_dport. Non-IPv4 sockets
 * are passed through; the sendpage_observed counter still bumps on every
 * call so userspace can see sendpage was exercised at all.
 */
SEC("lsm/socket_sendpage")
int BPF_PROG(lsm_socket_sendpage, struct socket *sock, struct page *page,
	     int offset, size_t size, int flags)
{
	lsm_bump_percpu_u32(&sendpage_observed);

	if (!lsm_defense_enabled())
		return 0;
	if (!sock)
		return 0;

	struct sock *sk = NULL;
	bpf_probe_read_kernel(&sk, sizeof(sk), &sock->sk);
	if (!sk)
		return 0;

	__u16 sk_family = 0;
	bpf_probe_read_kernel(&sk_family, sizeof(sk_family),
			      &sk->__sk_common.skc_family);
	if (sk_family != AF_INET)
		return 0;

	short protocol = 0;
	bpf_probe_read_kernel(&protocol, sizeof(protocol), &sk->sk_protocol);
	__u8 proto = (protocol == IPPROTO_UDP) ? COLDSTEP_PROTO_UDP : COLDSTEP_PROTO_TCP;

	__be32 daddr = 0;
	__be16 dport = 0;
	bpf_probe_read_kernel(&daddr, sizeof(daddr),
			      &sk->__sk_common.skc_daddr);
	bpf_probe_read_kernel(&dport, sizeof(dport),
			      &sk->__sk_common.skc_dport);

	if (daddr == 0)
		return 0;

	if (lsm_dst_in_ignored(daddr))
		return 0;
	if (lsm_dst_is_allowlisted(daddr))
		return 0;

	__u8 addr_bytes[4];
	__builtin_memcpy(addr_bytes, &daddr, sizeof(addr_bytes));
	lsm_emit_deny_event_ipv4(proto, addr_bytes, dport, COLDSTEP_DENY_REASON_DST_NOT_ALLOWLISTED);

	return -EPERM;
}
