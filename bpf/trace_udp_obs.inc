/* UDP sendto observability (IPv4 sendto → udp_events ringbuf). */
#ifndef TRACE_UDP_OBS_INC
#define TRACE_UDP_OBS_INC

static __always_inline void handle_udp_obs_emit(__be16 sin_port, __be32 sin_addr, __u32 len)
{
	struct udp_send_event *ue =
		bpf_ringbuf_reserve(&udp_events, sizeof(*ue), 0);
	if (!ue) {
		note_udp_ringbuf_reserve_failed();
		return;
	}
	{
		__u64 pt = bpf_get_current_pid_tgid();

		ue->tgid = (__u32)(pt >> 32);
		ue->tid = (__u32)pt;
	}
	bpf_get_current_comm(&ue->comm, sizeof(ue->comm));
	__builtin_memcpy(ue->daddr, &sin_addr, sizeof(ue->daddr));
	__builtin_memcpy(ue->dport, &sin_port, sizeof(ue->dport));
	ue->datagram_len = len;
	bpf_ringbuf_submit(ue, 0);
}

#endif /* TRACE_UDP_OBS_INC */
