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
#define COLDSTEP_NR_CLOSE 57
#define COLDSTEP_NR_RECVFROM 207
#elif defined(bpf_target_x86)
#define COLDSTEP_NR_CONNECT 42
#define COLDSTEP_NR_SENDTO 44
#define COLDSTEP_NR_SENDMSG 46
#define COLDSTEP_NR_WRITE 1
#define COLDSTEP_NR_CLOSE 3
#define COLDSTEP_NR_RECVFROM 45
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
 * Strict kernels (GitHub ubuntu-22.04 image + Azure 6.x, etc.) track syscall-derived lengths as
 * scalars whose signed min/max confuse bpf_probe_read_user size (R2). Keep one clamp+mask path
 * per sniff type so the verifier proves a tight unsigned upper bound on the read size register.
 */
static __always_inline __u32 coldstep_probe_user_sz_http(__u32 len_in)
{
	__u32 s = len_in;

	if (s > HTTP_PAYLOAD_MAX)
		s = HTTP_PAYLOAD_MAX;
	s &= 0xffu;
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

struct connect_event {
	__u32 tgid;
	__u32 tid;
	__u8 comm[16];
	__u8 daddr[4];
	__u8 dport[2];
};

struct udp_send_event {
	__u32 tgid;
	__u32 tid;
	__u8 comm[16];
	__u8 daddr[4];
	__u8 dport[2];
	__u32 datagram_len;
};

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
	/* GET / POST / HEAD / PUT — space or T for POST */
	if (p[0] == 'G' && p[1] == 'E' && p[2] == 'T' && p[3] == ' ')
		return 1;
	if (p[0] == 'P' && p[1] == 'O' && p[2] == 'S' && p[3] == 'T')
		return 1;
	if (p[0] == 'H' && p[1] == 'E' && p[2] == 'A' && p[3] == 'D')
		return 1;
	if (p[0] == 'P' && p[1] == 'U' && p[2] == 'T' && p[3] == ' ')
		return 1;
	return 0;
}

#endif /* TRACE_CONNECT_OBS_H */
