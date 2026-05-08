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
