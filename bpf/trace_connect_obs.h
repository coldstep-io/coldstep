/* Shared observability helpers for trace_connect.bpf.c (included fragments). */
#ifndef TRACE_CONNECT_OBS_H
#define TRACE_CONNECT_OBS_H

/*
 * raw_tp/sys_enter: ctx->args[0] is struct pt_regs * (see trace_connect.bpf.c).
 * Syscall NR + register layout follow bpf_target_* / __TARGET_ARCH_* (see traceconnect go generate).
 */

#ifndef AF_INET
#define AF_INET 2
#endif

/* bpf_tracing.h (included before this header) sets bpf_target_* from __TARGET_ARCH_* (see go generate). */
/*
 * Use only bpf_target_* (from bpf_tracing.h + -D__TARGET_ARCH_* from go generate).
 * Do not use __x86_64__ / __aarch64__: clang may define the host arch even when
 * CO-RE vmlinux.h matches __TARGET_ARCH_* (breaks ARM runners: x86 field names on arm64 pt_regs).
 */
#if defined(bpf_target_arm64)
#define COLDSTEP_NR_CONNECT 203
#define COLDSTEP_NR_SENDTO 206
#define COLDSTEP_NR_SENDMSG 211
#define COLDSTEP_NR_WRITE 64
/* COLDSTEP_NR_CLOSE retained for reference; close(2) FD cleanup removed — LRU eviction handles stale entries. */
#define COLDSTEP_NR_CLOSE 57
#define COLDSTEP_NR_RECVFROM 207
#define COLDSTEP_NR_RECVMSG 212
#define COLDSTEP_NR_READ 63
#define COLDSTEP_NR_WRITEV 66
/* PR-E: NRs for syscalls we do NOT fully observe, used by the unobserved-egress counter. */
#define COLDSTEP_NR_SENDMMSG 269
#define COLDSTEP_NR_PWRITE64 68
#define COLDSTEP_NR_PWRITEV 70
#define COLDSTEP_NR_PWRITEV2 287
#define COLDSTEP_NR_SENDFILE 71
#define COLDSTEP_NR_SPLICE 76
/* io_uring_setup detection: NR 425 on both x86_64 and aarch64 (unified since kernel 5.1). */
#define COLDSTEP_NR_IO_URING_SETUP 425
/* bpf syscall audit: 280 on arm64 */
#define COLDSTEP_NR_BPF 280
/* aarch64 has no legacy NR_OPEN: only openat/openat2 (handled in trace_fs.bpf.c). */
#elif defined(bpf_target_x86)
#define COLDSTEP_NR_CONNECT 42
#define COLDSTEP_NR_SENDTO 44
#define COLDSTEP_NR_SENDMSG 46
#define COLDSTEP_NR_WRITE 1
/* COLDSTEP_NR_CLOSE retained for reference; close(2) FD cleanup removed — LRU eviction handles stale entries. */
#define COLDSTEP_NR_CLOSE 3
#define COLDSTEP_NR_RECVFROM 45
#define COLDSTEP_NR_RECVMSG 47
#define COLDSTEP_NR_READ 0
#define COLDSTEP_NR_WRITEV 20
/* PR-E: NRs for syscalls we do NOT fully observe, used by the unobserved-egress counter. */
#define COLDSTEP_NR_SENDMMSG 307
#define COLDSTEP_NR_PWRITE64 18
#define COLDSTEP_NR_PWRITEV 296
#define COLDSTEP_NR_PWRITEV2 328
#define COLDSTEP_NR_SENDFILE 40
#define COLDSTEP_NR_SPLICE 275
/* io_uring_setup detection: NR 425 on both x86_64 and aarch64 (unified since kernel 5.1). */
#define COLDSTEP_NR_IO_URING_SETUP 425
/* bpf syscall audit: 321 on x86_64 */
#define COLDSTEP_NR_BPF 321
#else
#error "coldstep trace_connect: unsupported BPF arch (need bpf_target_x86/arm64 or __TARGET_ARCH_* from go generate)"
#endif

/* x86_64 syscall ABI uses rdi,rsi,rdx,r10,r8,r9 for args 1-6 (not rcx for arg4). */
static __always_inline int ns_read_syscall_arg(struct pt_regs *regs, unsigned int idx,
					       unsigned long *out)
{
	if (!regs || !out || idx > 5)
		return -1;

#if defined(bpf_target_x86)
	switch (idx) {
	case 0:
		return bpf_core_read(out, sizeof(*out), &regs->di);
	case 1:
		return bpf_core_read(out, sizeof(*out), &regs->si);
	case 2:
		return bpf_core_read(out, sizeof(*out), &regs->dx);
	case 3:
		return bpf_core_read(out, sizeof(*out), &regs->r10);
	case 4:
		return bpf_core_read(out, sizeof(*out), &regs->r8);
	case 5:
		return bpf_core_read(out, sizeof(*out), &regs->r9);
	default:
		return -1;
	}
#elif defined(bpf_target_arm64)
	switch (idx) {
	case 0:
		return bpf_core_read(out, sizeof(*out), &regs->regs[0]);
	case 1:
		return bpf_core_read(out, sizeof(*out), &regs->regs[1]);
	case 2:
		return bpf_core_read(out, sizeof(*out), &regs->regs[2]);
	case 3:
		return bpf_core_read(out, sizeof(*out), &regs->regs[3]);
	case 4:
		return bpf_core_read(out, sizeof(*out), &regs->regs[4]);
	case 5:
		return bpf_core_read(out, sizeof(*out), &regs->regs[5]);
	default:
		return -1;
	}
#else
	return -1;
#endif
}

/* Syscall NR at sys_exit (x86: orig_ax; arm64: syscallno in struct pt_regs BTF). */
static __always_inline int coldstep_read_orig_syscall_nr(struct pt_regs *regs, unsigned long *out)
{
	if (!regs || !out)
		return -1;
#if defined(bpf_target_x86)
	return bpf_core_read(out, sizeof(*out), &regs->orig_ax);
#elif defined(bpf_target_arm64)
	{
		__s32 nr;

		if (bpf_core_read(&nr, sizeof(nr), &regs->syscallno))
			return -1;
		*out = (unsigned long)nr;
	}
	return 0;
#else
	return -1;
#endif
}

#include "coldstep_pure.h"

/*
 * LP64 glibc/Linux iovec layout (x86_64 + aarch64):
 *   offsetof(iov_base) = 0  (pointer, 8 bytes)
 *   offsetof(iov_len)  = 8  (size_t, 8 bytes)
 * Used by trace_udp_sendmsg.inc (msghdr->msg_iov[0]) and
 * trace_tls_write.inc (writev iovec[0]) to extract buffer + length.
 */
struct coldstep_iovec {
	unsigned long iov_base;
	unsigned long iov_len;
};

/* Last IPv4 connect tuple observed for (tgid, fd); used to attribute TLS ClientHello writes. */
struct connect4_tuple {
	__u8 daddr[4];
	__u8 dport[2];
	__u8 in_use;
	__u8 _pad;
};

struct tls_sniff_event {
	__u32 tgid;
	__u32 tid;
	__u8 comm[16];
	__u8 daddr[4];
	__u8 dport[2];
	__u8 _pad[2];
	__u16 capture_len;
	__u8 payload[TLS_PAYLOAD_MAX];
};
/*
 * Layout: header(34) + payload[256]; alignment-of-4 trailing pad → sizeof = 292.
 * Go decoder caps capture_len at 256 and never touches the trailing pad.
 */
_Static_assert(sizeof(struct tls_sniff_event) == 292,
	       "tls_sniff_event wire size must match tlsSniffEventWireSize=292 in agent_linux.go");

struct connect_event {
	__u32 tgid;
	__u32 tid;
	__u8 comm[16];
	__u8 daddr[4];
	__u8 dport[2];
};
/*
 * Implicit struct alignment is 4 bytes (largest member __u32). The
 * 30-byte field layout is padded by clang to 32 bytes; the Go decoder
 * (decodeConnectEvent) reads the first 30 bytes and ignores the trailing
 * 2 bytes. connectEventWireSize in agent_linux.go must mirror this.
 */
_Static_assert(sizeof(struct connect_event) == 32,
	       "connect_event wire size must match connectEventWireSize=32 in agent_linux.go");

/*
 * `_pad[2]` is required to make the 4-byte alignment of `datagram_len`
 * explicit. Without it, clang inserts implicit padding between dport[2]
 * (offset 28) and datagram_len at offset 32; that left the Go decoder
 * (decodeUDPSendEvent) reading dgramLen from offset 30 which yielded
 * garbage. The explicit pad here forces the layout the Go side now
 * decodes (offset 32) and is locked by the _Static_assert below.
 */
struct udp_send_event {
	__u32 tgid;
	__u32 tid;
	__u8 comm[16];
	__u8 daddr[4];
	__u8 dport[2];
	__u8 _pad[2];
	__u32 datagram_len;
};
_Static_assert(sizeof(struct udp_send_event) == 36,
	       "udp_send_event wire size must match udpSendEventWireSize=36 in agent_linux.go");

struct http_sniff_event {
	__u32 tgid;
	__u32 tid;
	__u8 comm[16];
	__u8 daddr[4];
	__u8 dport[2];
	__u8 _pad[2];
	__u16 capture_len;
	__u8 payload[HTTP_PAYLOAD_MAX];
};
/*
 * Layout: header(34) + payload[192]; struct alignment of 4 forces a 2-byte
 * trailing pad → sizeof = 228. The Go decoder caps capture_len at 192 and
 * never touches the trailing pad.
 */
_Static_assert(sizeof(struct http_sniff_event) == 228,
	       "http_sniff_event wire size must match httpSniffEventWireSize=228 in agent_linux.go");

static __always_inline int read_ipv4_sockaddr(unsigned long sockaddr_ptr, __be16 *port,
					      __be32 *addr)
{
	/*
	 * One bounded userspace read (Linux struct sockaddr_in layout for AF_INET).
	 * Avoid (char *)sa+N follow-up probe reads — older kernels mis-track sizes/pointers
	 * (Verifier: bpf_probe_read_user … R2 min value is negative).
	 */
	__u8 scratch[16];

	if (!sockaddr_ptr || !port || !addr)
		return -1;
	if (bpf_probe_read_user(scratch, sizeof(scratch), (void *)sockaddr_ptr))
		return -1;
	return coldstep_parse_ipv4_sockaddr16(scratch, port, addr);
}

static __always_inline int http_prefix_looks_like_request(unsigned long buf_ptr, __u32 cap)
{
	char p[4];

	if (cap < 4)
		return 0;
	if (!buf_ptr)
		return 0;
	/* Constant size 4 for strict verifiers (see read_ipv4_sockaddr). */
	if (bpf_probe_read_user(p, 4, (void *)buf_ptr))
		return 0;
	return coldstep_http_prefix_is_request(p);
}

#endif /* TRACE_CONNECT_OBS_H */
