/*
 * Pure helpers shared by BPF programs and userspace unit tests (no bpf_* APIs).
 * Include after Linux/__vmlinux integer typedefs when built for BPF.
 *
 * For host tests: #define COLDSTEP_PURE_HOST_TEST before including this header.
 */
#ifndef COLDSTEP_PURE_H
#define COLDSTEP_PURE_H

#ifdef COLDSTEP_PURE_HOST_TEST
#include <stdint.h>
typedef uint8_t __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint16_t __be16;
typedef uint32_t __be32;
#endif

#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef AF_INET6
#define AF_INET6 10
#endif

#ifndef __always_inline
#define __always_inline inline __attribute__((__always_inline__))
#endif

#define HTTP_PAYLOAD_MAX 192
#define TLS_PAYLOAD_MAX 256

/*
 * bpf_core_read of syscall registers yields unsigned long scalars; some kernel verifiers still
 * infer signed-range quirks once those values reach bpf_probe_read_user size (R2). Force an
 * explicit low-32-bit domain before length feeds HTTP/TLS sniff helpers.
 */
static __always_inline __u32 coldstep_syscall_len_u32(unsigned long raw)
{
	return (__u32)(raw & 0xffffffffULL);
}

/*
 * Strict kernels track syscall-derived lengths as scalars whose signed min/max confuse
 * bpf_probe_read_user size (R2). Keep one clamp+mask path per sniff type so the verifier
 * proves a tight unsigned upper bound on the read size register.
 */
static __always_inline __u32 coldstep_probe_user_sz_http(__u32 len_in)
{
	__u32 s = len_in;

	if (s > HTTP_PAYLOAD_MAX)
		s = HTTP_PAYLOAD_MAX;
	s &= 0xffu; /* 255: smallest 2^n-1 >= HTTP_PAYLOAD_MAX(192); verifier range proof */
	if (s > HTTP_PAYLOAD_MAX)
		s = HTTP_PAYLOAD_MAX;
	return s;
}

static __always_inline __u32 coldstep_probe_user_sz_tls(__u32 len_in)
{
	__u32 s = len_in;

	if (s > TLS_PAYLOAD_MAX)
		s = TLS_PAYLOAD_MAX;
	s &= 0x1ffu;
	if (s > TLS_PAYLOAD_MAX)
		s = TLS_PAYLOAD_MAX;
	return s;
}

/*
 * Parse the first 16 bytes of a Linux struct sockaddr_in image (AF_INET only).
 * Used by read_ipv4_sockaddr after bpf_probe_read_user(scratch, 16, ...).
 */
static __always_inline int coldstep_parse_ipv4_sockaddr16(const __u8 scratch[16], __be16 *port,
							  __be32 *addr)
{
	if (!scratch || !port || !addr)
		return -1;
	{
		__u16 family;

		__builtin_memcpy(&family, scratch, sizeof(family));
		if (family != (__u16)AF_INET)
			return -1;
	}
	__builtin_memcpy(port, scratch + 2, sizeof(*port));
	__builtin_memcpy(addr, scratch + 4, sizeof(*addr));
	return 0;
}

/*
 * Parse the first 24 bytes of a Linux struct sockaddr_in6 image (AF_INET6 only).
 * Layout: sin6_family(2) sin6_port(2) sin6_flowinfo(4) sin6_addr(16) [sin6_scope_id(4) skipped].
 * Used by read_ipv6_sockaddr after bpf_probe_read_user(scratch, 24, ...).
 */
static __always_inline int coldstep_parse_ipv6_sockaddr24(const __u8 scratch[24], __be16 *port,
							  __u8 addr[16])
{
	if (!scratch || !port || !addr)
		return -1;
	{
		__u16 family;

		__builtin_memcpy(&family, scratch, sizeof(family));
		if (family != (__u16)AF_INET6)
			return -1;
	}
	__builtin_memcpy(port, scratch + 2, sizeof(*port));
	__builtin_memcpy(addr, scratch + 8, 16);
	return 0;
}

/*
 * 127.0.0.0/8 loopback test on a network-byte-order IPv4 address. Byte 0 of
 * the in-memory representation is the first dotted octet regardless of host
 * endianness, so no htonl is needed — keeps this header pure / host-testable.
 * Used by defend_policy.inc:dst_in_ignored so every IPv4 defend hook (cgroup
 * connect4/sendmsg4, LSM connect/sendmsg/sendpage, v4-mapped IPv6 branches)
 * bypasses loopback: it is not egress, and denying it breaks the
 * systemd-resolved stub (127.0.0.53:53) that GitHub-hosted runners resolve
 * through, failing every getaddrinfo with EAI_AGAIN in defend mode.
 */
static __always_inline int coldstep_ipv4_is_loopback(__be32 daddr)
{
	__u8 first_octet;

	__builtin_memcpy(&first_octet, &daddr, 1);
	return first_octet == 127;
}

/*
 * 0.0.0.0 (INADDR_ANY) as a connect(2)/sendmsg(2) destination. The kernel's
 * IPv4 connect path (inet_stream_connect / ip4_datagram_connect) transparently
 * rewrites a destination of INADDR_ANY to INADDR_LOOPBACK — but that rewrite
 * happens AFTER cgroup/connect4 and the LSM connect/sendmsg hooks observe the
 * destination, so without this check they see the raw 0.0.0.0 the caller
 * passed and deny it as a normal (non-loopback) destination even though the
 * kernel is about to route the connection to loopback. Empirically confirmed
 * against the real kernel and this agent's own defend-mode enforcement:
 * connect(("0.0.0.0", port)) succeeds and getpeername() reports 127.0.0.1,
 * while cgroup/connect4 logs a deny with dst=0.0.0.0 for the exact same call.
 */
static __always_inline int coldstep_ipv4_is_unspecified(__be32 daddr)
{
	return daddr == 0;
}

/*
 * :: (the unspecified IPv6 address) as a connect(2)/sendmsg(2) destination —
 * the IPv6 twin of coldstep_ipv4_is_unspecified, and bypassed for the same
 * reason. tcp_v6_connect() and ip6_datagram_connect() rewrite an all-zero
 * sin6_addr to in6addr_loopback (or to ::ffff:127.0.0.1 on a v4-mapped local
 * address) before the connection goes anywhere, but that rewrite happens AFTER
 * cgroup/connect6, cgroup/sendmsg6 and the LSM socket_connect/socket_sendmsg
 * hooks have already seen the destination — so without this check they judge the
 * raw :: against allowed_ipv6, miss, and deny a connection the kernel was about
 * to route to loopback.
 *
 * The LSM sendmsg path needs it for a second reason: when msg_name is absent it
 * falls back to skc_v6_daddr, which is all-zero on an unconnected socket. The
 * IPv4 side of that same fallback already treats daddr == 0 as "no destination,
 * do not judge"; this keeps the v6 side consistent instead of denying on a
 * destination it never actually read.
 *
 * `a` is the address as four network-byte-order __u32 words (the shape of
 * bpf_sock_addr.user_ip6, sock_common.skc_v6_daddr, and the skb_v6_* helpers).
 */
static __always_inline int coldstep_ipv6_is_unspecified(const __u32 a[4])
{
	return a[0] == 0 && a[1] == 0 && a[2] == 0 && a[3] == 0;
}

/* First four bytes of an HTTP request line (after userspace read). */
static __always_inline int coldstep_http_prefix_is_request(const char p[4])
{
	if (p[0] == 'G' && p[1] == 'E' && p[2] == 'T' && p[3] == ' ')
		return 1;
	if (p[0] == 'P' && p[1] == 'O' && p[2] == 'S' && p[3] == 'T')
		return 1;
	if (p[0] == 'H' && p[1] == 'E' && p[2] == 'A' && p[3] == 'D')
		return 1;
	if (p[0] == 'P' && p[1] == 'U' && p[2] == 'T' && p[3] == ' ')
		return 1;
	if (p[0] == 'D' && p[1] == 'E' && p[2] == 'L' && p[3] == 'E')
		return 1;
	if (p[0] == 'P' && p[1] == 'A' && p[2] == 'T' && p[3] == 'C')
		return 1;
	if (p[0] == 'O' && p[1] == 'P' && p[2] == 'T' && p[3] == 'I')
		return 1;
	if (p[0] == 'C' && p[1] == 'O' && p[2] == 'N' && p[3] == 'N')
		return 1;
	return 0;
}

#endif /* COLDSTEP_PURE_H */
