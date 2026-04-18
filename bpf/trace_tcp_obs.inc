/* TCP connect observability (__NR_connect → connect_events ringbuf). */
#ifndef TRACE_TCP_OBS_INC
#define TRACE_TCP_OBS_INC

/* Register values read in handle_raw_sys_enter (verifier-friendly on 6.17+). */
static __always_inline int handle_tcp_obs_connect(__u32 fd32, unsigned long sockaddr_ptr)
{
	__be16 sin_port;
	__be32 sin_addr;

	if (!sockaddr_ptr)
		return 0;
	if (read_ipv4_sockaddr(sockaddr_ptr, &sin_port, &sin_addr))
		return 0;

	struct connect_event *ce =
		bpf_ringbuf_reserve(&connect_events, sizeof(*ce), 0);
	if (!ce) {
		note_connect_ringbuf_reserve_failed();
		return 0;
	}
	{
		__u64 pt = bpf_get_current_pid_tgid();

		ce->tgid = (__u32)(pt >> 32);
		ce->tid = (__u32)pt;
	}
	bpf_get_current_comm(&ce->comm, sizeof(ce->comm));
	__builtin_memcpy(ce->daddr, &sin_addr, sizeof(ce->daddr));
	__builtin_memcpy(ce->dport, &sin_port, sizeof(ce->dport));
	bpf_ringbuf_submit(ce, 0);

	{
		struct connect4_tuple tup = {};

		__builtin_memcpy(tup.daddr, &sin_addr, sizeof(sin_addr));
		__builtin_memcpy(tup.dport, &sin_port, sizeof(sin_port));
		tup.in_use = 1;
		{
			__u64 pt = bpf_get_current_pid_tgid();
			__u32 tgid = (__u32)(pt >> 32);
			__u64 mkey = ((__u64)tgid << 32) | (__u64)fd32;

			if (bpf_map_update_elem(&connect4_by_tgid_fd, &mkey, &tup, BPF_ANY))
				note_connect4_tuple_update_failed();
		}
	}
	return 0;
}

#endif /* TRACE_TCP_OBS_INC */
