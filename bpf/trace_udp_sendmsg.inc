/* UDP sendmsg observability — extract IPv4 dst + length from userspace msghdr, then udp_events. */
#ifndef TRACE_UDP_SENDMSG_INC
#define TRACE_UDP_SENDMSG_INC

/*
 * glibc/Linux LP64 userspace layout (verified for x86_64 + aarch64):
 *   offsetof(msg_name)    = 0
 *   offsetof(msg_namelen)   = 8   (socklen_t 4 + padding before msg_iov)
 *   offsetof(msg_iov)       = 16
 *   offsetof(msg_iovlen)    = 24  (size_t)
 */
struct coldstep_iovec {
	unsigned long iov_base;
	unsigned long iov_len;
};

static __always_inline int coldstep_udp_len_from_msghdr(unsigned long msg_hdr_ptr, __u32 *out_len)
{
	unsigned long msg_iov = 0;
	unsigned long msg_iovlen = 0;
	struct coldstep_iovec iov0 = {};

	if (!msg_hdr_ptr || !out_len)
		return -1;

	if (bpf_probe_read_user(&msg_iov, sizeof(msg_iov), (void *)(msg_hdr_ptr + 16)))
		return -1;
	if (bpf_probe_read_user(&msg_iovlen, sizeof(msg_iovlen), (void *)(msg_hdr_ptr + 24)))
		return -1;
	if (!msg_iov || msg_iovlen == 0) {
		*out_len = 0;
		return 0;
	}
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

	if (!msg_hdr_ptr || !sin_port || !sin_addr)
		return -1;

	if (bpf_probe_read_user(&msg_name, sizeof(msg_name), (void *)msg_hdr_ptr))
		return -1;
	if (bpf_probe_read_user(&msg_namelen, sizeof(msg_namelen), (void *)(msg_hdr_ptr + 8)))
		return -1;

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
