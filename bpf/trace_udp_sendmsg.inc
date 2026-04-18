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
 */
static __always_inline int coldstep_read_msghdr_head32(unsigned long msg_hdr_ptr, __u8 *out32)
{
	if (!msg_hdr_ptr || !out32)
		return -1;
	if (bpf_probe_read_user(out32, 32, (void *)msg_hdr_ptr))
		return -1;
	return 0;
}

static __always_inline int coldstep_udp_len_from_msghdr(unsigned long msg_hdr_ptr, __u32 *out_len)
{
	unsigned long msg_iov = 0;
	unsigned long msg_iovlen = 0;
	struct coldstep_iovec iov0 = {};
	__u8 hdr[32];

	if (!msg_hdr_ptr || !out_len)
		return -1;

	if (coldstep_read_msghdr_head32(msg_hdr_ptr, hdr))
		return -1;
	__builtin_memcpy(&msg_iov, hdr + 16, sizeof(msg_iov));
	__builtin_memcpy(&msg_iovlen, hdr + 24, sizeof(msg_iovlen));
	if (!msg_iov || msg_iovlen == 0) {
		*out_len = 0;
		return 0;
	}
	/*
	 * Multi-iovec visibility: surface scatter/gather sendmsg calls so
	 * operators see the rate of payload-fragmentation we don't observe past
	 * iov[0]. Counter wired to udpSendmsgMultiIovecObservedN in agent_linux.go.
	 */
	if (msg_iovlen > 1)
		note_udp_sendmsg_multi_iovec();
	if (bpf_probe_read_user(&iov0, sizeof(iov0), (void *)msg_iov))
		return -1;
	if (iov0.iov_len > 0x00100000)
		*out_len = 0x00100000;
	else
		*out_len = (__u32)iov0.iov_len;
	return 0;
}

static __always_inline int coldstep_udp_dest_from_sendmsg(unsigned long msg_hdr_ptr, __u32 fd32,
							  __be16 *sin_port, __be32 *sin_addr)
{
	unsigned long msg_name = 0;
	__u32 msg_namelen = 0;
	__u8 hdr[32];

	if (!msg_hdr_ptr || !sin_port || !sin_addr)
		return -1;

	if (coldstep_read_msghdr_head32(msg_hdr_ptr, hdr))
		return -1;
	__builtin_memcpy(&msg_name, hdr, sizeof(msg_name));
	__builtin_memcpy(&msg_namelen, hdr + 8, sizeof(msg_namelen));

	if (msg_name && msg_namelen >= 16 /* sizeof(struct sockaddr_in) userspace */) {
		if (!read_ipv4_sockaddr(msg_name, sin_port, sin_addr))
			return 0;
	}

	{
		__u64 pt = bpf_get_current_pid_tgid();
		__u32 tgid = (__u32)(pt >> 32);
		__u64 mkey = ((__u64)tgid << 32) | (__u64)fd32;
		struct connect4_tuple *tup = bpf_map_lookup_elem(&connect4_by_tgid_fd, &mkey);

		if (!tup || !tup->in_use)
			return -1;
		__builtin_memcpy(sin_port, tup->dport, sizeof(*sin_port));
		__builtin_memcpy(sin_addr, tup->daddr, sizeof(*sin_addr));
		return 0;
	}
}

static __always_inline int handle_udp_obs_sendmsg(__u32 fd32, unsigned long msg_hdr_ptr)
{
	__be16 sin_port = 0;
	__be32 sin_addr = 0;
	__u32 len = 0;

	if (coldstep_udp_dest_from_sendmsg(msg_hdr_ptr, fd32, &sin_port, &sin_addr))
		return 0;
	if (coldstep_udp_len_from_msghdr(msg_hdr_ptr, &len))
		return 0;
	handle_udp_obs_emit(sin_port, sin_addr, len);
	return 0;
}

#endif /* TRACE_UDP_SENDMSG_INC */
