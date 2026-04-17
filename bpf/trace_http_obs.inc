/* Cleartext HTTP/1 request sniff on IPv4 sendto to dport 80 (http_events ringbuf). */
#ifndef TRACE_HTTP_OBS_INC
#define TRACE_HTTP_OBS_INC

static __always_inline void handle_http_obs_emit(unsigned long buf_ptr, __u32 len,
						 __be16 sin_port, __be32 sin_addr)
{
	struct http_sniff_event *he =
		bpf_ringbuf_reserve(&http_events, sizeof(*he), 0);
	if (!he)
		return;
	{
		__u64 pt = bpf_get_current_pid_tgid();

		he->tgid = (__u32)(pt >> 32);
		he->tid = (__u32)pt;
	}
	bpf_get_current_comm(&he->comm, sizeof(he->comm));
	__builtin_memcpy(he->daddr, &sin_addr, sizeof(he->daddr));
	__builtin_memcpy(he->dport, &sin_port, sizeof(he->dport));
	he->_pad[0] = 0;
	he->_pad[1] = 0;
	{
		/*
		 * Verifier (GitHub ubuntu-22.04 / 6.8-azure): variable bpf_probe_read_user size
		 * from syscall-derived scalars may keep R2 in a signed-range merge even after masks
		 * (see iovisor/bcc#2391, #5251). Read the full destination array with a compile-time
		 * constant size; capture_len still reflects the bounded logical length.
		 */
		_Static_assert(sizeof(he->payload) == HTTP_PAYLOAD_MAX,
			       "http sniff payload array vs HTTP_PAYLOAD_MAX");
		__u32 sz = coldstep_probe_user_sz_http(len);

		he->capture_len = (__u16)sz;
		if (bpf_probe_read_user(he->payload, sizeof(he->payload), (void *)buf_ptr)) {
			bpf_ringbuf_discard(he, 0);
			return;
		}
	}
	bpf_ringbuf_submit(he, 0);
}

#endif /* TRACE_HTTP_OBS_INC */
