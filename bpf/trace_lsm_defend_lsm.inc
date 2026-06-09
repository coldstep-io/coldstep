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
 * IPv6 LSM defense-in-depth twin (ORDER 4 / Phase 4.2). The cgroup connect6/
 * sendmsg6 hooks already enforce native IPv6 against allowed_ipv6; this gives
 * the LSM layer the same coverage on kernels that boot with `bpf` in the LSM
 * chain, mirroring how lsm_socket_connect/sendmsg twin the cgroup IPv4 path.
 * Hand-written (not via the defend_policy.inc template) so the v6 deny is
 * emitted into the LSM's own renamed ring (lsm_deny_events) without having to
 * thread a new templated symbol through every includer.
 *
 * Reuses the byte-buffer v6 helpers from trace_defend_skb.inc
 * (skb_v6_is_loopback / _link_local / _v4mapped / _is_allowlisted), which is
 * included before this file, and the IPv4 allowlist/ignored/deny helpers above
 * for the v4-mapped case.
 */
static __always_inline void lsm_emit_deny_event_ipv6(__u8 protocol,
						     const __u8 *dst16, __be16 dport,
						     __u8 reason)
{
	/* AUDIT(5b): submit/discard paired — only exit between reserve and submit
	 * is the `!de` early return (no slot held). */
	struct deny_event *de = bpf_ringbuf_reserve(&lsm_deny_events, sizeof(*de), 0);

	if (!de) {
		lsm_note_deny_ring_reserve_failed();
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
	__builtin_memset(de->daddr, 0, sizeof(de->daddr));
	if (dst16)
		__builtin_memcpy(de->daddr, dst16, 16);
	__builtin_memcpy(de->dport, &dport, sizeof(de->dport));
	bpf_ringbuf_submit(de, 0);
}

/*
 * Enforce a 16-byte network-order IPv6 destination against the allowlist.
 * Returns -EPERM (deny) or 0 (allow). ::1 and fe80::/10 always allow; IPv4-
 * mapped destinations are judged against the IPv4 allowlist (the wire traffic
 * is v4), exactly mirroring defend_cgroup_sock_addr_ipv6. defense_enabled is
 * already checked by the caller for the native-v6 path; the v4-mapped branch
 * re-checks via the IPv4 helpers which are inert when defense is off.
 */
static __always_inline int lsm_v6_enforce(__u8 proto, const __u8 daddr16[16],
					  __be16 dport)
{
	__u32 a[4];
	__builtin_memcpy(a, daddr16, sizeof(a));

	if (skb_v6_is_loopback(a))
		return 0;
	if (skb_v6_is_link_local(a))
		return 0;

	if (skb_v6_is_v4mapped(a)) {
		__be32 v4 = a[3]; /* embedded IPv4, network byte order */
		__u8 addr4[4];

		if (lsm_dst_in_ignored(v4))
			return 0;
		if (lsm_dst_is_allowlisted(v4))
			return 0;
		__builtin_memcpy(addr4, &v4, sizeof(addr4));
		lsm_emit_deny_event_ipv4(proto, addr4, dport,
					 COLDSTEP_DENY_REASON_DST_NOT_ALLOWLISTED);
		return -EPERM;
	}

	if (skb_v6_is_allowlisted(daddr16))
		return 0;

	lsm_emit_deny_event_ipv6(proto, daddr16, dport,
				 COLDSTEP_DENY_REASON_DST_NOT_ALLOWLISTED);
	return -EPERM;
}

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
	/*
	 * AUDIT(5f): explicit zero-init for defense in depth. Kernel 5.5+ zeros
	 * `bpf_probe_read_*` destinations on failure (so a probe miss leaves
	 * these as zero and fails the AF_INET / NULL guards below), but the
	 * sibling `lsm_socket_sendmsg` path also zero-inits — keep the two
	 * patterns consistent so a future copy-paste cannot regress to reading
	 * stack garbage on pre-5.5 kernels or under verifier mode changes.
	 */
	short family = 0;
	/* AUDIT(5f): return intentionally not checked — destination is zeroed on
	 * failure and the AF_INET guard below fails closed (0 != AF_INET). */
	bpf_probe_read_kernel(&family, sizeof(family), &addr4->sin_family);

	/*
	 * ORDER 4: native IPv6 connect. Defense is already enabled (checked at
	 * the top of the hook). Read the 16-byte sin6_addr + sin6_port and the
	 * socket protocol, then enforce against allowed_ipv6 (v4-mapped is judged
	 * against the IPv4 allowlist inside lsm_v6_enforce).
	 */
	if (family == AF_INET6) {
		if (addrlen < (int)sizeof(struct sockaddr_in6))
			return 0;
		struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)address;
		__u8 d16[16] = {};
		__be16 dport6 = 0;
		/* AUDIT(5f): returns not checked — zero-init means a probe miss
		 * yields ::/0:0 which is judged like any other dst (fail-closed
		 * against the allowlist, not a crash). */
		bpf_probe_read_kernel(d16, sizeof(d16), &addr6->sin6_addr);
		bpf_probe_read_kernel(&dport6, sizeof(dport6), &addr6->sin6_port);

		struct sock *sk6 = NULL;
		bpf_probe_read_kernel(&sk6, sizeof(sk6), &sock->sk);
		short protocol6 = 0;
		if (sk6)
			bpf_probe_read_kernel(&protocol6, sizeof(protocol6),
					      &sk6->sk_protocol);
		__u8 proto6 = (protocol6 == IPPROTO_UDP) ? COLDSTEP_PROTO_UDP
							 : COLDSTEP_PROTO_TCP;
		return lsm_v6_enforce(proto6, d16, dport6);
	}

	if (family != AF_INET)
		return 0;

	struct sock *sk = NULL;
	/* AUDIT(5f): return intentionally not checked — `sk` zero-init + NULL
	 * guard below means a probe failure fails closed. */
	bpf_probe_read_kernel(&sk, sizeof(sk), &sock->sk);
	if (!sk)
		return 0;

	short protocol = 0;
	/* AUDIT(5f): return intentionally not checked — `protocol` zero-init
	 * defaults to TCP (0 != IPPROTO_UDP), which is the conservative label
	 * for the deny event when the read can't be trusted. */
	bpf_probe_read_kernel(&protocol, sizeof(protocol), &sk->sk_protocol);

	__u8 proto = (protocol == IPPROTO_UDP) ? COLDSTEP_PROTO_UDP : COLDSTEP_PROTO_TCP;

	__be32 daddr = 0;
	__be16 dport = 0;
	/* AUDIT(5f): return intentionally not checked — both destinations are
	 * zero-initialized so a probe miss yields daddr=0 / dport=0 and the
	 * allowlist / ignored-trie checks below behave deterministically. */
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
	/* AUDIT(5a): null checked — only used inside `if (val)`. */
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
	/* AUDIT(5f): return intentionally not checked — `sk` zero-init + NULL
	 * guard fails closed. */
	bpf_probe_read_kernel(&sk, sizeof(sk), &sock->sk);
	if (!sk)
		return 0;

	short protocol = 0;
	/* AUDIT(5f): return intentionally not checked — `protocol` zero-init
	 * defaults to TCP for the deny-event label. */
	bpf_probe_read_kernel(&protocol, sizeof(protocol), &sk->sk_protocol);
	__u8 proto = (protocol == IPPROTO_UDP) ? COLDSTEP_PROTO_UDP : COLDSTEP_PROTO_TCP;

	struct sockaddr *address = NULL;
	int namelen = 0;
	/* AUDIT(5f): return intentionally not checked — both vars are
	 * zero-initialized; downstream `if (address && namelen >= …)` falls
	 * through to the sock_common-derived peer path on failure. */
	bpf_probe_read_kernel(&address, sizeof(address), &msg->msg_name);
	bpf_probe_read_kernel(&namelen, sizeof(namelen), &msg->msg_namelen);

	/*
	 * ORDER 4: native IPv6 sendmsg. When the socket is AF_INET6, take the dst
	 * from an explicit sockaddr_in6 msg_name (unconnected send) or fall back
	 * to the connected peer in sock_common (skc_v6_daddr). v4-mapped dsts are
	 * gated against the IPv4 allowlist inside lsm_v6_enforce.
	 */
	{
		__u16 sk_fam6 = 0;
		bpf_probe_read_kernel(&sk_fam6, sizeof(sk_fam6),
				      &sk->__sk_common.skc_family);
		if (sk_fam6 == AF_INET6) {
			__u8 d16[16] = {};
			__be16 dport6 = 0;

			if (address && namelen >= (int)sizeof(struct sockaddr_in6)) {
				struct sockaddr_in6 *a6 = (struct sockaddr_in6 *)address;

				bpf_probe_read_kernel(d16, sizeof(d16), &a6->sin6_addr);
				bpf_probe_read_kernel(&dport6, sizeof(dport6),
						      &a6->sin6_port);
			} else {
				bpf_probe_read_kernel(d16, sizeof(d16),
						      &sk->__sk_common.skc_v6_daddr);
				bpf_probe_read_kernel(&dport6, sizeof(dport6),
						      &sk->__sk_common.skc_dport);
			}
			return lsm_v6_enforce(proto, d16, dport6);
		}
	}

	__be32 daddr = 0;
	__be16 dport = 0;

	if (address && namelen >= (int)sizeof(struct sockaddr_in)) {
		if (read_ipv4_sockaddr((unsigned long)address, &dport, &daddr))
			return 0;
	} else {
		__u16 sk_family = 0;
		/* AUDIT(5f): return intentionally not checked — zero-init + the
		 * `!= AF_INET` guard below fails closed on probe failure. */
		bpf_probe_read_kernel(&sk_family, sizeof(sk_family),
				      &sk->__sk_common.skc_family);
		if (sk_family != AF_INET)
			return 0;

		/* AUDIT(5f): return intentionally not checked — `daddr` /
		 * `dport` zero-init mean a probe miss yields daddr=0, and the
		 * `daddr == 0` guard below fails closed. */
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
	/* AUDIT(5f): return intentionally not checked — zero-init + NULL guard. */
	bpf_probe_read_kernel(&sk, sizeof(sk), &sock->sk);
	if (!sk)
		return 0;

	__u16 sk_family = 0;
	/* AUDIT(5f): return intentionally not checked — zero-init + AF_INET guard. */
	bpf_probe_read_kernel(&sk_family, sizeof(sk_family),
			      &sk->__sk_common.skc_family);
	if (sk_family != AF_INET)
		return 0;

	short protocol = 0;
	/* AUDIT(5f): return intentionally not checked — zero-init defaults to TCP. */
	bpf_probe_read_kernel(&protocol, sizeof(protocol), &sk->sk_protocol);
	__u8 proto = (protocol == IPPROTO_UDP) ? COLDSTEP_PROTO_UDP : COLDSTEP_PROTO_TCP;

	__be32 daddr = 0;
	__be16 dport = 0;
	/* AUDIT(5f): return intentionally not checked — zero-init + `daddr == 0` guard. */
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
