/*
 * TLS ClientHello + plaintext HTTP/1 sniff on IPv4 TCP buffers.
 *
 * Dispatch:
 *   - write(2) / writev(2) / pwrite64(2) / pwritev(2) / pwritev2(2): handled here via
 *     handle_write_obs_sys_enter (tuple from fd map; first three syscall args match write/writev ABI).
 *     One LRU lookup feeds both TLS and HTTP/80 sniff (mirrors the sendto arm in trace_connect.bpf.c).
 *   - sendto(2): handled in trace_connect.bpf.c NR_SENDTO — builds connect4_tuple from
 *     cached connect tuple OR explicit sockaddr-in (parity with HTTP sendto path).
 */
#ifndef TRACE_TLS_WRITE_INC
#define TRACE_TLS_WRITE_INC

/*
 * Emit TLS sniff using connect4_tuple-shaped daddr/dport + caller pt (no fd map lookup here).
 * NR_write/NR_writev resolve tuple via coldstep_connect_tuple_fetch first; NR_sendto passes
 * tuple from trace_connect.bpf.c (cached connect or sockaddr-synthesized stack tuple).
 */
static __always_inline void try_emit_tls_clienthello_from_tuple(struct connect4_tuple *tup,
								unsigned long buf_ptr,
								__u32 len_in,
								__u64 pt)
{
	{
		__u32 key0 = 0;
		/* AUDIT(5a): null checked — `!en` short-circuits before `*en`. */
		__u8 *en = bpf_map_lookup_elem(&tls_agent_cfg, &key0);

		if (!en || *en == 0)
			return;
	}

	__u32 len = coldstep_probe_user_sz_tls(len_in);

	if (len < 6 || !buf_ptr)
		return;

	if (!tup || !tup->in_use)
		return;

	{
		unsigned char peek[6];

		/* Constant read size — variable peeksz trips strict verifiers on some runners. */
		/* AUDIT(5f): return checked — non-zero aborts before deref. */
		if (bpf_probe_read_user(peek, 6, (void *)buf_ptr))
			return;
		if (peek[0] != 0x16)   /* ContentType: Handshake */
			return;
		if (peek[1] != 0x03)   /* LegacyRecordVersion major byte */
			return;
		/* Minor byte: 0x00–0x04 covers SSLv3 through TLS 1.3 legacy values. */
		if (peek[2] > 0x04)
			return;
		if (peek[5] != 0x01)   /* HandshakeType: ClientHello */
			return;
	}

	{
		__u32 tgid = (__u32)(pt >> 32);
		/* AUDIT(5b): submit/discard paired — `!ev` early return holds
		 * no slot; the probe-read-failure path discards before return;
		 * success submits at end of block. */
		struct tls_sniff_event *ev =
			bpf_ringbuf_reserve(&tls_events, sizeof(*ev), 0);

		if (!ev) {
			note_tls_ringbuf_reserve_failed();
			return;
		}
		ev->tgid = tgid;
		ev->tid = (__u32)pt;
		bpf_get_current_comm(&ev->comm, sizeof(ev->comm));
		__builtin_memcpy(ev->daddr, tup->daddr, sizeof(ev->daddr));
		__builtin_memcpy(ev->dport, tup->dport, sizeof(ev->dport));
		ev->_pad[0] = 0;
		ev->_pad[1] = 0;
		{
			/*
			 * Constant read size for strict verifiers (same pattern as HTTP sniff —
			 * variable len trips R2 on some matrix legs; see trace_http_obs.inc).
			 */
			_Static_assert(sizeof(ev->payload) == TLS_PAYLOAD_MAX,
				       "tls sniff payload array vs TLS_PAYLOAD_MAX");
			ev->capture_len = (__u16)len;
			/* AUDIT(5f): return checked — non-zero discards the reserved slot. */
			if (bpf_probe_read_user(ev->payload, sizeof(ev->payload), (void *)buf_ptr)) {
				bpf_ringbuf_discard(ev, 0);
				return;
			}
		}
		bpf_ringbuf_submit(ev, 0);
	}
}

/*
 * Run both TLS-ClientHello and HTTP/80 sniff against a single buffer using a
 * pre-fetched (tgid,fd) tuple. Used by handle_write_obs_sys_enter so each
 * write/writev/pwrite* dispatch does at most one connect4_by_tgid_fd lookup.
 * Mirrors the sendto arm in trace_connect.bpf.c (TLS + HTTP from one tuple).
 */
static __always_inline void try_emit_buffer_sniff_from_tuple(struct connect4_tuple *tup,
							     unsigned long buf_ptr, __u32 len,
							     __u64 pt)
{
	try_emit_tls_clienthello_from_tuple(tup, buf_ptr, len, pt);

	if (!tup || !tup->in_use)
		return;

	{
		__be16 sin_port;
		__be32 sin_addr;

		__builtin_memcpy(&sin_port, tup->dport, sizeof(sin_port));
		__builtin_memcpy(&sin_addr, tup->daddr, sizeof(sin_addr));

		if (sin_port == bpf_htons(80) && len >= 4 &&
		    http_prefix_looks_like_request(buf_ptr, len))
			handle_http_obs_emit_pt(pt, buf_ptr, len, sin_port, sin_addr);
	}
}

/*
 * write/writev/pwrite64/pwritev/pwritev2 dispatch: fetch (tgid,fd) tuple once,
 * run TLS ClientHello sniff (any port) and HTTP/1 plaintext sniff (dport 80).
 * di/si/dx are syscall arg registers as read in handle_raw_sys_enter.
 */
static __always_inline int handle_write_obs_sys_enter(long id, unsigned long di_ul,
						      unsigned long si_ul, unsigned long dx_ul)
{
	struct connect4_tuple tup;
	__u64 pt;

	if (coldstep_connect_tuple_fetch((__u32)di_ul, &tup, &pt))
		return 0;

	if (id == (long)COLDSTEP_NR_WRITE || id == (long)COLDSTEP_NR_PWRITE64) {
		/* fd, buf, count — same first-three-arg layout for write and pwrite64
		 * (pwrite64 offset is arg3, ignored for sniff). */
		try_emit_buffer_sniff_from_tuple(&tup, si_ul, coldstep_syscall_len_u32(dx_ul),
						 pt);
		return 0;
	}

	if (id == (long)COLDSTEP_NR_WRITEV ||
	    id == (long)COLDSTEP_NR_PWRITEV ||
	    id == (long)COLDSTEP_NR_PWRITEV2) {
		struct coldstep_iovec iov0 = {};
		if (dx_ul > 0 && si_ul) {
			/*
			 * Multi-iovec visibility: writev's `vlen` arg (dx_ul) > 1
			 * means scatter/gather payload. The counter still fires to
			 * surface the rate of fragmented writes; BG-02 added a
			 * bounded peek at iov[1] below so the second segment is no
			 * longer silently dropped from sniff. Counter wired to
			 * tlsWritevMultiIovecObservedN in agent_linux.go.
			 */
			if (dx_ul > 1)
				note_tls_writev_multi_iovec();
			/* AUDIT(5f): return checked — only the `== 0` branch
			 * proceeds; on probe failure iov0 stays {} and the
			 * sniff is skipped. */
			if (bpf_probe_read_user(&iov0, sizeof(iov0), (void *)si_ul) == 0) {
				/*
				 * iov_len comes from untrusted userspace memory. Cap it to
				 * TLS_PAYLOAD_MAX before the sniff call as defence-in-depth;
				 * coldstep_probe_user_sz_tls() would also clamp, but an
				 * explicit pre-cap keeps the verifier scalar range tight and
				 * makes the intent self-documenting.
				 */
				__u32 iov_len = coldstep_syscall_len_u32(iov0.iov_len);
				if (iov_len > TLS_PAYLOAD_MAX)
					iov_len = TLS_PAYLOAD_MAX;
				try_emit_buffer_sniff_from_tuple(&tup, iov0.iov_base, iov_len,
								 pt);

				/*
				 * BG-02 (C1, bounded): some writev callers split the
				 * record so iov[0] holds a small header (length prefix
				 * or framing byte) and iov[1] holds the TLS
				 * ClientHello body. The dispatch helper rejects
				 * non-TLS / non-HTTP prefixes internally, so doing a
				 * second bounded peek at iov[1] is safe — at worst the
				 * fingerprint also fails on iov[1] and nothing is
				 * emitted. Strictly capped at index 1; no iov walk.
				 */
				if (dx_ul >= 2) {
					struct coldstep_iovec iov1 = {};
					/* AUDIT(5c): pointer arithmetic bounded — `si_ul` is
					 * the userspace iovec[] base; `+ sizeof(coldstep_iovec)`
					 * advances to iov[1]. The kernel performs the actual
					 * bounds check inside bpf_probe_read_user; a short
					 * iovec array yields a non-zero return below and the
					 * branch is skipped.
					 * AUDIT(5f): return checked — only `== 0` proceeds. */
					if (bpf_probe_read_user(&iov1, sizeof(iov1),
						(void *)(si_ul + sizeof(struct coldstep_iovec))) == 0) {
						__u32 iov1_len = coldstep_syscall_len_u32(iov1.iov_len);
						if (iov1_len > TLS_PAYLOAD_MAX)
							iov1_len = TLS_PAYLOAD_MAX;
						try_emit_buffer_sniff_from_tuple(&tup,
										 iov1.iov_base,
										 iov1_len, pt);
					}
				}
			}
		}
		return 0;
	}

	return 0;
}

#endif /* TRACE_TLS_WRITE_INC */
