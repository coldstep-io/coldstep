/*
 * cgroup_skb egress backstop section of bpf/trace_defend_all.bpf.c (sub-project
 * A). Observe-only: flags packets reaching the cgroup egress hook bound for a
 * non-allowlisted, non-ignored, non-loopback IP in defend mode — egress that
 * bypassed connect4/sendmsg4 (raw socket / AF_PACKET / post-connect redirect).
 * ALWAYS returns 1 (allow); never drops.
 *
 * MUST be #include'd AFTER the cgroup section so the address-based helpers
 * cg_defense_enabled / cg_dst_in_ignored / cg_dst_is_allowlisted and the
 * allowed_ipv6 map are already in scope. Reuses defend_lpm_v6_key.h.
 *
 * cgroup_skb egress skb begins at L3 (no L2 header). skb->protocol selects the
 * family. Reads are bounded via bpf_skb_load_bytes; every return is checked and
 * on failure the packet is allowed (observe-only fail-open).
 */

#ifndef ETH_P_IP
#define ETH_P_IP   0x0800
#endif
#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD
#endif

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 16);
} skb_backstop_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} skb_backstop_reserve_failures SEC(".maps");

struct skb_backstop_seen_key {
	__u8 addr[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1024);
	__type(key, struct skb_backstop_seen_key);
	__type(value, __u64);
} skb_backstop_seen SEC(".maps");

#define COLDSTEP_SKB_BACKSTOP_COOLDOWN_NS 1000000000ULL /* 1s */

static __always_inline void skb_note_backstop_reserve_failed(void)
{
	__u32 k = 0;
	/* AUDIT(5a): null checked — early return guards (*v)++. */
	__u32 *v = bpf_map_lookup_elem(&skb_backstop_reserve_failures, &k);

	if (!v)
		return;
	(*v)++;
}

static __always_inline int skb_backstop_recently_seen(const __u8 addr[16])
{
	struct skb_backstop_seen_key key = {};
	__u64 now = bpf_ktime_get_ns();

	__builtin_memcpy(key.addr, addr, sizeof(key.addr));
	/* AUDIT(5a): null checked. */
	__u64 *last = bpf_map_lookup_elem(&skb_backstop_seen, &key);
	if (last && (now - *last) < COLDSTEP_SKB_BACKSTOP_COOLDOWN_NS)
		return 1;
	bpf_map_update_elem(&skb_backstop_seen, &key, &now, BPF_ANY);
	return 0;
}

static __always_inline int skb_v4_is_loopback(__be32 daddr)
{
	return (daddr & bpf_htonl(0xff000000)) == bpf_htonl(0x7f000000);
}

static __always_inline int skb_v6_is_loopback(const __u32 a[4])
{
	return a[0] == 0 && a[1] == 0 && a[2] == 0 && a[3] == bpf_htonl(1);
}

static __always_inline int skb_v6_is_link_local(const __u32 a[4])
{
	return (a[0] & bpf_htonl(0xffc00000)) == bpf_htonl(0xfe800000);
}

static __always_inline int skb_v6_is_v4mapped(const __u32 a[4])
{
	return a[0] == 0 && a[1] == 0 && a[2] == bpf_htonl(0x0000ffff);
}

static __always_inline int skb_v6_is_allowlisted(const __u8 addr[16])
{
	struct lpm_v6_key k = {};

	k.prefixlen = 128;
	__builtin_memcpy(k.addr, addr, sizeof(k.addr));
	/* AUDIT(5a): null checked — pointer used only as boolean. */
	__u8 *ok = bpf_map_lookup_elem(&allowed_ipv6, &k);
	return ok != 0;
}

static __always_inline void skb_emit_backstop(struct __sk_buff *skb, __u8 af,
					      __u8 ipproto, const __u8 daddr[16],
					      const __u8 dport[2])
{
	/* AUDIT(5b): submit/discard paired — only exit before submit is the
	 * `!ev` early return (no slot held). */
	struct egress_backstop_event *ev =
		bpf_ringbuf_reserve(&skb_backstop_events, sizeof(*ev), 0);

	if (!ev) {
		skb_note_backstop_reserve_failed();
		return;
	}
	ev->timestamp_ns = bpf_ktime_get_ns();
	ev->pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
	bpf_get_current_comm(&ev->comm, sizeof(ev->comm));
	ev->af = af;
	ev->ipproto = ipproto;
	ev->_pad[0] = ev->_pad[1] = 0;
	__builtin_memcpy(ev->daddr, daddr, sizeof(ev->daddr));
	ev->dport[0] = dport[0];
	ev->dport[1] = dport[1];
	__builtin_memset(ev->_pad2, 0, sizeof(ev->_pad2));
	bpf_ringbuf_submit(ev, 0);
}

SEC("cgroup_skb/egress")
int defend_skb_egress(struct __sk_buff *skb)
{
	if (!cg_defense_enabled())
		return 1;

	if (skb->protocol == bpf_htons(ETH_P_IP)) {
		__u8 ihl_ver = 0, ipproto = 0;
		__be32 daddr = 0;
		__u8 dport[2] = {0, 0};

		/* AUDIT(5f): every load return checked; failure => allow. */
		if (bpf_skb_load_bytes(skb, 0, &ihl_ver, 1))
			return 1;
		if (bpf_skb_load_bytes(skb, 9, &ipproto, 1))
			return 1;
		if (bpf_skb_load_bytes(skb, 16, &daddr, 4))
			return 1;

		if (skb_v4_is_loopback(daddr))
			return 1;

		/*
		 * TEMP DIAGNOSTIC (sub-project A evidence cycle — REVERT BEFORE MERGE):
		 * emit BEFORE the ignored/allowlist filters so the integration test
		 * reveals (a) whether cgroup_skb/egress fires for these packets at all
		 * and (b) exactly what dst the hook reads. The emitted event's dst
		 * distinguishes "hook never runs" (no event) from "filter wrongly
		 * suppressed" (event with dst=1.1.1.1) from "offset bug" (event with
		 * a wrong dst). dport is left 0 for the diagnostic.
		 */
		{
			__u8 a16[16] = {};

			__builtin_memcpy(a16, &daddr, 4);
			if (!skb_backstop_recently_seen(a16))
				skb_emit_backstop(skb, AF_INET, ipproto, a16, dport);
		}
		return 1;
	}

	if (skb->protocol == bpf_htons(ETH_P_IPV6)) {
		__u8 nexthdr = 0;
		__u8 a16[16] = {};
		__u32 a4[4];
		__u8 dport[2] = {0, 0};

		if (bpf_skb_load_bytes(skb, 6, &nexthdr, 1))
			return 1;
		if (bpf_skb_load_bytes(skb, 24, a16, 16))
			return 1;
		__builtin_memcpy(a4, a16, sizeof(a4));

		if (skb_v6_is_loopback(a4))
			return 1;
		if (skb_v6_is_link_local(a4))
			return 1;

		if (skb_v6_is_v4mapped(a4)) {
			__be32 v4 = a4[3];

			if (cg_dst_in_ignored(v4))
				return 1;
			if (cg_dst_is_allowlisted(v4))
				return 1;
		} else if (skb_v6_is_allowlisted(a16)) {
			return 1;
		}

		(void)bpf_skb_load_bytes(skb, 40 + 2, dport, 2);

		if (skb_backstop_recently_seen(a16))
			return 1;

		skb_emit_backstop(skb, AF_INET6, nexthdr, a16, dport);
		return 1;
	}

	return 1;
}
