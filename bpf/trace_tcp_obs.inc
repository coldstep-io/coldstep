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

	/* AUDIT(5b): submit/discard paired — only exit between reserve and
	 * submit is the `!ce` early return (no slot held). Submit unconditional. */
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
		bpf_get_current_comm(&ce->comm, sizeof(ce->comm));
		__builtin_memcpy(ce->daddr, &sin_addr, sizeof(ce->daddr));
		__builtin_memcpy(ce->dport, &sin_port, sizeof(ce->dport));
		bpf_ringbuf_submit(ce, 0);

		{
			struct connect4_tuple tup = {};

			__builtin_memcpy(tup.daddr, &sin_addr, sizeof(sin_addr));
			__builtin_memcpy(tup.dport, &sin_port, sizeof(sin_port));
			tup.in_use = 1;
			tup.is_ipv6 = 0;
			{
				__u32 tgid = (__u32)(pt >> 32);
				__u64 mkey = ((__u64)tgid << 32) | (__u64)fd32;

				/* AUDIT(5a): update failure surfaced via percpu counter;
				 * LRU map evicts stale entries automatically. */
				if (bpf_map_update_elem(&connect4_by_tgid_fd, &mkey, &tup, BPF_ANY))
					note_connect4_tuple_update_failed();
			}
		}
	}
	return 0;
}

/*
 * IPv6 connect observability (P5): mirrors handle_tcp_obs_connect but reads
 * sockaddr_in6 and stores the v6 address into the tuple LRU map so the TLS
 * sniff path can attribute ClientHello writes on the same fd. No IPv6
 * connect_events ringbuf record is emitted — `connect_event` has an IPv4-only
 * wire shape and TCP-IPv6 events would need a separate ringbuf to surface
 * (out of scope for the SNI-only P5 increment).
 */
static __always_inline int handle_tcp_obs_connect6(__u32 fd32, unsigned long sockaddr_ptr)
{
	__be16 sin6_port;
	__u8 sin6_addr[16];

	if (!sockaddr_ptr)
		return 0;
	if (read_ipv6_sockaddr(sockaddr_ptr, &sin6_port, sin6_addr))
		return 0;

	{
		__u64 pt = bpf_get_current_pid_tgid();
		struct connect4_tuple tup = {};

		__builtin_memcpy(tup.daddr6, sin6_addr, sizeof(tup.daddr6));
		__builtin_memcpy(tup.dport, &sin6_port, sizeof(tup.dport));
		tup.in_use = 1;
		tup.is_ipv6 = 1;
		{
			__u32 tgid = (__u32)(pt >> 32);
			__u64 mkey = ((__u64)tgid << 32) | (__u64)fd32;

			/* AUDIT(5a): update failure surfaced via percpu counter;
			 * LRU map evicts stale entries automatically. */
			if (bpf_map_update_elem(&connect4_by_tgid_fd, &mkey, &tup, BPF_ANY))
				note_connect4_tuple_update_failed();
		}
	}
	return 0;
}

#endif /* TRACE_TCP_OBS_INC */
