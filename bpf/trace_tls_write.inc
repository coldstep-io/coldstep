/* TLS ClientHello sniff on IPv4 TCP (write(2) or sendto(2) with NULL dest), correlated with prior connect(2). */
#ifndef TRACE_TLS_WRITE_INC
#define TRACE_TLS_WRITE_INC

/* Shared by __NR_write and __NR_sendto (connected TCP often uses sendto(fd, buf, len, flags, NULL, 0)). */
static __always_inline void try_emit_tls_clienthello(__u32 fd32, unsigned long buf_ptr, __u32 len_in)
{
	{
		__u32 key0 = 0;
		__u8 *en = bpf_map_lookup_elem(&tls_agent_cfg, &key0);

		if (!en || *en == 0)
			return;
	}

	__u32 len = coldstep_probe_user_sz_tls(len_in);

	if (len < 6 || !buf_ptr)
		return;

	{
		__u64 pt = bpf_get_current_pid_tgid();
		__u32 tgid = (__u32)(pt >> 32);
		__u64 mkey = ((__u64)tgid << 32) | (__u64)fd32;
		struct connect4_tuple *tup = bpf_map_lookup_elem(&connect4_by_tgid_fd, &mkey);

		if (!tup || !tup->in_use)
			return;

		{
			unsigned char peek[8];

			/* Constant read size — variable peeksz trips strict verifiers on some runners. */
			if (bpf_probe_read_user(peek, 6, (void *)buf_ptr))
				return;
			if (peek[0] != 0x16)
				return;
			if (peek[1] != 0x03)
				return;
			if (peek[5] != 0x01)
				return;
		}

		{
			struct tls_sniff_event *ev =
				bpf_ringbuf_reserve(&tls_events, sizeof(*ev), 0);

			if (!ev)
				return;
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
				if (bpf_probe_read_user(ev->payload, sizeof(ev->payload), (void *)buf_ptr)) {
					bpf_ringbuf_discard(ev, 0);
					return;
				}
			}
			bpf_ringbuf_submit(ev, 0);
		}
	}
}

/* id + syscall arg registers; di/si/dx read only in handle_raw_sys_enter. */
static __always_inline int handle_tls_obs_sys_enter(long id, unsigned long di_ul,
						   unsigned long si_ul, unsigned long dx_ul)
{
	if (id == (long)COLDSTEP_NR_CLOSE) {
		__u32 fd32 = (__u32)di_ul;
		{
			__u64 pt = bpf_get_current_pid_tgid();
			__u32 tgid = (__u32)(pt >> 32);
			__u64 mkey = ((__u64)tgid << 32) | (__u64)fd32;

			bpf_map_delete_elem(&connect4_by_tgid_fd, &mkey);
		}
		return 0;
	}

	if (id != (long)COLDSTEP_NR_WRITE)
		return 0;

	try_emit_tls_clienthello((__u32)di_ul, si_ul, coldstep_syscall_len_u32(dx_ul));
	return 0;
}

#endif /* TRACE_TLS_WRITE_INC */
