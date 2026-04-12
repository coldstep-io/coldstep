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
		__u32 sz = len;

		if (sz > HTTP_PAYLOAD_MAX)
			sz = HTTP_PAYLOAD_MAX;
		/* Verifier (e.g. Ubuntu 22.04 / Azure 6.8): bpf_probe_read_user size must be a tight unsigned bound. */
		sz &= 0xffu;
		he->capture_len = (__u16)sz;
		if (bpf_probe_read_user(he->payload, sz, (void *)buf_ptr)) {
			bpf_ringbuf_discard(he, 0);
			return;
		}
	}
	bpf_ringbuf_submit(he, 0);
}

#endif /* TRACE_HTTP_OBS_INC */
