/*
 * IPv4 sendto/sendmsg-length observability → `udp_events` ringbuf.
 * Despite the map name, payloads here include TCP segments sent via `sendto`/`sendmsg` paths
 * (same helper); distinguish by protocol in userspace from JSONL / digest if needed.
 */
#ifndef TRACE_UDP_OBS_INC
#define TRACE_UDP_OBS_INC

static __always_inline void handle_udp_obs_emit_pt(__u64 pt, __be16 sin_port, __be32 sin_addr,
						    __u32 len)
{
	struct udp_send_event *ue =
		bpf_ringbuf_reserve(&udp_events, sizeof(*ue), 0);
	if (!ue) {
		note_udp_ringbuf_reserve_failed();
		return;
	}
	ue->tgid = (__u32)(pt >> 32);
	ue->tid = (__u32)pt;
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

static __always_inline void handle_udp_obs_emit(__be16 sin_port, __be32 sin_addr, __u32 len)
{
	__u64 pt = bpf_get_current_pid_tgid();

	handle_udp_obs_emit_pt(pt, sin_port, sin_addr, len);
}

/*
 * Copy full tuple from (tgid,fd) LRU map — basis for dst extraction and TLS
 * sniff on connected sendto (single lookup shared across udp_events + tls_events).
 * Writes bpf_get_current_pid_tgid() once into *pt_out for downstream emit_pt.
 */
static __always_inline int coldstep_connect_tuple_fetch(__u32 fd32, struct connect4_tuple *out,
							__u64 *pt_out)
{
	__u64 pt = bpf_get_current_pid_tgid();
	__u32 tgid = (__u32)(pt >> 32);
	__u64 mkey = ((__u64)tgid << 32) | (__u64)fd32;
	struct connect4_tuple *tup = bpf_map_lookup_elem(&connect4_by_tgid_fd, &mkey);

	if (!tup || !tup->in_use || !out || !pt_out)
		return -1;
	__builtin_memcpy(out, tup, sizeof(*out));
	*pt_out = pt;
	return 0;
}

/*
 * Resolve IPv4 dst from tuple map — sendfile/splice and sendmsg fallback paths.
 */
static __always_inline int coldstep_tuple_dst_for_fd(__u32 fd32, __be16 *sin_port,
						     __be32 *sin_addr, __u64 *pt_out)
{
	struct connect4_tuple t;

	if (coldstep_connect_tuple_fetch(fd32, &t, pt_out))
		return -1;
	__builtin_memcpy(sin_port, t.dport, sizeof(*sin_port));
	__builtin_memcpy(sin_addr, t.daddr, sizeof(*sin_addr));
	return 0;
}

#endif /* TRACE_UDP_OBS_INC */
