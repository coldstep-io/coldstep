/*
 * IPv4 sendto/sendmsg-length observability → `udp_events` ringbuf.
 * Despite the map name, payloads here include TCP segments sent via `sendto`/`sendmsg` paths
 * (same helper); distinguish by protocol in userspace from JSONL / digest if needed.
 */
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
	/*
	 * `_pad[2]` aligns datagram_len; ringbuf_reserve memory is
	 * uninitialized so explicitly zero the pad before submit to avoid
	 * leaking stale kernel bytes into telemetry (mirrors trace_http_obs.inc
	 * which zeroes he->_pad for the same reason). Per-field zeroing keeps
	 * the verifier happy on strict 6.x kernels — __builtin_memset of the
	 * whole struct can interact poorly with subsequent field stores.
	 */
	ue->_pad[0] = 0;
	ue->_pad[1] = 0;
	ue->datagram_len = len;
	bpf_ringbuf_submit(ue, 0);
}

#endif /* TRACE_UDP_OBS_INC */
