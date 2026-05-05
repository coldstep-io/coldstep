/* UDP sendmsg observability — extract IPv4 dst + length from userspace msghdr, then udp_events. */
#ifndef TRACE_UDP_SENDMSG_INC
#define TRACE_UDP_SENDMSG_INC

/*
 * LP64 glibc msghdr layout (x86_64 + aarch64, verified):
 *   msg_name    @ 0  (void *, 8 bytes)
 *   msg_namelen @ 8  (socklen_t 4 bytes + 4-byte pad)
 *   msg_iov     @ 16 (struct iovec *, 8 bytes)
 *   msg_iovlen  @ 24 (size_t, 8 bytes)
 *
 * Read as a single 32-byte slab so the verifier sees one bounded probe rather
 * than multiple ptr+offset reads (strict 6.x kernels reject chained probes).
 * struct coldstep_iovec layout is documented in trace_connect_obs.h.
 *
 * handle_udp_obs_sendmsg reads the slab once and derives both destination and
 * iov[0] length — previously destination and length helpers each issued a full
 * 32-byte bpf_probe_read_user of the same msghdr.
 */
static __always_inline int coldstep_read_msghdr_head32(unsigned long msg_hdr_ptr, __u8 *out32)
{
	if (!msg_hdr_ptr || !out32)
		return -1;
	if (bpf_probe_read_user(out32, 32, (void *)msg_hdr_ptr))
		return -1;
	return 0;
}

static __always_inline int handle_udp_obs_sendmsg(__u32 fd32, unsigned long msg_hdr_ptr)
{
	__u8 hdr[32];
	__be16 sin_port = 0;
	__be32 sin_addr = 0;
	__u32 len = 0;
	unsigned long msg_name = 0;
	__u32 msg_namelen = 0;
	unsigned long msg_iov = 0;
	unsigned long msg_iovlen = 0;
	struct coldstep_iovec iov0 = {};

	if (!msg_hdr_ptr)
		return 0;

	if (coldstep_read_msghdr_head32(msg_hdr_ptr, hdr))
		return 0;

	__builtin_memcpy(&msg_name, hdr, sizeof(msg_name));
	__builtin_memcpy(&msg_namelen, hdr + 8, sizeof(msg_namelen));

	if (msg_name && msg_namelen >= 16 /* sizeof(struct sockaddr_in) userspace */) {
		if (!read_ipv4_sockaddr(msg_name, &sin_port, &sin_addr))
			goto have_dest;
	}

	if (coldstep_tuple_dst_for_fd(fd32, &sin_port, &sin_addr))
		return 0;

have_dest:

	__builtin_memcpy(&msg_iov, hdr + 16, sizeof(msg_iov));
	__builtin_memcpy(&msg_iovlen, hdr + 24, sizeof(msg_iovlen));
	if (!msg_iov || msg_iovlen == 0) {
		len = 0;
	} else {
		/*
		 * Multi-iovec visibility: surface scatter/gather sendmsg calls so
		 * operators see the rate of payload-fragmentation we don't observe past
		 * iov[0]. Counter wired to udpSendmsgMultiIovecObservedN in agent_linux.go.
		 */
		if (msg_iovlen > 1)
			note_udp_sendmsg_multi_iovec();
		if (bpf_probe_read_user(&iov0, sizeof(iov0), (void *)msg_iov))
			return 0;
		if (iov0.iov_len > 0x00100000)
			len = 0x00100000;
		else
			len = (__u32)iov0.iov_len;
	}

	handle_udp_obs_emit(sin_port, sin_addr, len);
	return 0;
}

#endif /* TRACE_UDP_SENDMSG_INC */
