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
	int use_tuple_pt = 0;
	__u64 tuple_pt = 0;

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

	if (coldstep_tuple_dst_for_fd(fd32, &sin_port, &sin_addr, &tuple_pt))
		return 0;
	use_tuple_pt = 1;

have_dest:

	__builtin_memcpy(&msg_iov, hdr + 16, sizeof(msg_iov));
	__builtin_memcpy(&msg_iovlen, hdr + 24, sizeof(msg_iovlen));
	if (!msg_iov || msg_iovlen == 0) {
		len = 0;
	} else {
		/*
		 * Multi-iovec visibility: surface scatter/gather sendmsg calls so
		 * operators see the rate of payload-fragmentation. Counter still fires
		 * so the historical metric stays comparable; BG-02 added the bounded
		 * iov[1] peek below so iov[1] is no longer silently dropped from
		 * TLS/HTTP sniff. Counter wired to udpSendmsgMultiIovecObservedN in
		 * agent_linux.go.
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

	if (use_tuple_pt)
		handle_udp_obs_emit_pt(tuple_pt, sin_port, sin_addr, len);
	else
		handle_udp_obs_emit(sin_port, sin_addr, len);

	/*
	 * BG-02 (C1, bounded): historically only iov[0] length was extracted
	 * for the udp_send_event; iov[1+] payloads were silently dropped from
	 * TLS/HTTP sniff. When the sendmsg buffer is split (e.g. header in
	 * iov[0], TLS ClientHello / HTTP request line in iov[1]) the protocol
	 * fingerprint lives in iov[1]. Do one bounded peek at iov[1] and feed
	 * it through the existing sniff helpers — both gate on their own
	 * prefix tests, so non-matching payloads emit nothing. Strictly capped
	 * at index 1: no unlimited iov walk.
	 */
	if (msg_iov && msg_iovlen >= 2) {
		struct coldstep_iovec iov1 = {};

		if (bpf_probe_read_user(&iov1, sizeof(iov1),
					(void *)(msg_iov + sizeof(struct coldstep_iovec))) == 0) {
			__u32 iov1_len = coldstep_syscall_len_u32(iov1.iov_len);

			{
				__u32 tls_len = iov1_len;
				struct connect4_tuple st = {};
				__u64 pt_sniff = use_tuple_pt ? tuple_pt
							      : bpf_get_current_pid_tgid();

				if (tls_len > TLS_PAYLOAD_MAX)
					tls_len = TLS_PAYLOAD_MAX;
				st.in_use = 1;
				st._pad = 0;
				__builtin_memcpy(st.daddr, &sin_addr, sizeof(st.daddr));
				__builtin_memcpy(st.dport, &sin_port, sizeof(st.dport));
				try_emit_tls_clienthello_from_tuple(&st, iov1.iov_base,
								    tls_len, pt_sniff);
			}

			if (sin_port == bpf_htons(80)) {
				__u32 http_len = iov1_len;

				if (http_len > 0x00100000)
					http_len = 0x00100000;
				if (http_len >= 4 &&
				    http_prefix_looks_like_request(iov1.iov_base, http_len)) {
					if (use_tuple_pt)
						handle_http_obs_emit_pt(tuple_pt, iov1.iov_base,
									http_len, sin_port,
									sin_addr);
					else
						handle_http_obs_emit(iov1.iov_base, http_len,
								     sin_port, sin_addr);
				}
			}
		}
	}

	return 0;
}

/*
 * BG-03: stripped-down per-message helper for sendmmsg(2) extra slots (vlen > 1).
 *
 * Same msghdr layout reads as handle_udp_obs_sendmsg — destination from
 * msg_name/msg_namelen (fallback to coldstep_tuple_dst_for_fd), datagram_len
 * from iov[0].iov_len — but explicitly omits the iov[1] TLS/HTTP sniff peek
 * (BG-02) so the per-slot instruction budget stays well under the verifier
 * complexity ceiling when this helper is invoked from a #pragma unroll loop.
 *
 * Multi-message UDP datagrams in practice share a single connected
 * destination (the typical sendmmsg caller is QUIC/UDP send batching);
 * losing iov[1] sniff on messages 2..N is acceptable for a v0.2.x first
 * pass — message 0 still flows through the full handle_udp_obs_sendmsg
 * helper above, so TLS ClientHellos in the first message remain sniffed.
 *
 * Returns void: any error path silently bails (matches handle_udp_obs_sendmsg
 * convention where every early return is `return 0`).
 */
static __always_inline void handle_udp_obs_sendmsg_extra(__u32 fd32,
							  unsigned long msg_hdr_ptr)
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
	int use_tuple_pt = 0;
	__u64 tuple_pt = 0;

	if (!msg_hdr_ptr)
		return;

	if (coldstep_read_msghdr_head32(msg_hdr_ptr, hdr))
		return;

	__builtin_memcpy(&msg_name, hdr, sizeof(msg_name));
	__builtin_memcpy(&msg_namelen, hdr + 8, sizeof(msg_namelen));

	if (msg_name && msg_namelen >= 16 /* sizeof(struct sockaddr_in) userspace */) {
		if (!read_ipv4_sockaddr(msg_name, &sin_port, &sin_addr))
			goto have_dest;
	}

	if (coldstep_tuple_dst_for_fd(fd32, &sin_port, &sin_addr, &tuple_pt))
		return;
	use_tuple_pt = 1;

have_dest:

	__builtin_memcpy(&msg_iov, hdr + 16, sizeof(msg_iov));
	__builtin_memcpy(&msg_iovlen, hdr + 24, sizeof(msg_iovlen));
	if (!msg_iov || msg_iovlen == 0) {
		len = 0;
	} else {
		if (bpf_probe_read_user(&iov0, sizeof(iov0), (void *)msg_iov))
			return;
		if (iov0.iov_len > 0x00100000)
			len = 0x00100000;
		else
			len = (__u32)iov0.iov_len;
	}

	if (use_tuple_pt)
		handle_udp_obs_emit_pt(tuple_pt, sin_port, sin_addr, len);
	else
		handle_udp_obs_emit(sin_port, sin_addr, len);
}

#endif /* TRACE_UDP_SENDMSG_INC */
