/*
 * tc/clsact egress backstop section of bpf/trace_defend_all.bpf.c (sub-project
 * A). Observe-only: flags packets reaching the egress qdisc bound for a
 * non-allowlisted, non-ignored, non-loopback IP in defend mode — egress that
 * bypassed connect4/sendmsg4 (raw socket / AF_PACKET / post-connect redirect).
 * ALWAYS returns TC_ACT_OK (never drops).
 *
 * Mechanism note: an earlier revision used SEC("cgroup_skb/egress"), but a
 * cgroup_skb program attached to the agent's cgroup is never invoked for
 * locally-generated egress in this deployment (verified by local repro — a
 * sentinel emit at the top of the program produced zero events). tc/clsact
 * egress runs at the qdisc layer in __dev_queue_xmit and sees ALL egress
 * (including raw sockets) regardless of cgroup; attached per-interface via TCX.
 *
 * MUST be #include'd AFTER the cgroup section so the address-based helpers
 * cg_defense_enabled / cg_dst_in_ignored / cg_dst_is_allowlisted and the
 * allowed_ipv6 map are already in scope. Reuses defend_lpm_v6_key.h.
 *
 * At clsact egress the L2 header is not yet pushed, so skb->data points at the
 * network header (L3 / IP). The IP version is read from the high nibble of
 * byte 0. Reads are bounded via bpf_skb_load_bytes; every return is checked and
 * on failure the packet is passed (observe-only fail-open).
 */

#ifndef TC_ACT_OK
#define TC_ACT_OK 0
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

/* Returns 1 if the dst was seen within the cooldown (suppress), else 0 and
 * records now. Boolean — not a TC action. */
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
	/*
	 * tc/clsact egress runs in packet/softirq context with no reliable
	 * "current" task — bpf_get_current_pid_tgid / bpf_get_current_comm are
	 * not available to this program type. Leave pid=0 and comm empty; the
	 * egress_backstop_event doc already declares pid/comm best-effort, and
	 * dst/proto/af carry the signal.
	 */
	ev->pid = 0;
	__builtin_memset(ev->comm, 0, sizeof(ev->comm));
	ev->af = af;
	ev->ipproto = ipproto;
	ev->_pad[0] = ev->_pad[1] = 0;
	__builtin_memcpy(ev->daddr, daddr, sizeof(ev->daddr));
	ev->dport[0] = dport[0];
	ev->dport[1] = dport[1];
	__builtin_memset(ev->_pad2, 0, sizeof(ev->_pad2));
	bpf_ringbuf_submit(ev, 0);
}

SEC("tcx/egress")
int defend_skb_egress(struct __sk_buff *skb)
{
	if (!cg_defense_enabled())
		return TC_ACT_OK;

	/* LOCAL DIAGNOSTIC (revert): sentinel + raw byte0 in 2nd octet. */
	/*
	 * Read packet bytes relative to the NETWORK header. At tc/clsact egress the
	 * L2 (Ethernet) header may or may not be present depending on the interface
	 * (it IS present on Hyper-V/virtio NICs, absent on tun/wireguard), so a
	 * fixed offset-0 read is unreliable — it caught the L2 dst-MAC instead of
	 * the IP header in testing. bpf_skb_load_bytes_relative(..., BPF_HDR_START_NET)
	 * always reads from the IP header regardless of L2 presence.
	 * Determine the IP version from the high nibble of byte 0 (it doubles as the
	 * IPv4 version+IHL field). AUDIT(5f): load return checked; failure => pass.
	 */
	__u8 vbyte = 0;

	if (bpf_skb_load_bytes_relative(skb, 0, &vbyte, 1, BPF_HDR_START_NET))
		return TC_ACT_OK;

	if ((vbyte >> 4) == 4) {
		__u8 ipproto = 0;
		__be32 daddr = 0;
		__u8 dport[2] = {0, 0};

		/* AUDIT(5f): every load return checked; failure => pass. */
		if (bpf_skb_load_bytes_relative(skb, 9, &ipproto, 1, BPF_HDR_START_NET))
			return TC_ACT_OK;
		if (bpf_skb_load_bytes_relative(skb, 16, &daddr, 4, BPF_HDR_START_NET))
			return TC_ACT_OK;

		if (skb_v4_is_loopback(daddr))
			return TC_ACT_OK;
		if (cg_dst_in_ignored(daddr))
			return TC_ACT_OK;
		if (cg_dst_is_allowlisted(daddr))
			return TC_ACT_OK;

		{
			__u32 ihl = (vbyte & 0x0f);
			__u32 l4 = ihl * 4;

			if (ihl >= 5 && l4 <= 60)
				(void)bpf_skb_load_bytes_relative(skb, l4 + 2, dport, 2, BPF_HDR_START_NET);
		}

		{
			__u8 a16[16] = {};

			__builtin_memcpy(a16, &daddr, 4);
			if (skb_backstop_recently_seen(a16))
				return TC_ACT_OK;
			skb_emit_backstop(skb, AF_INET, ipproto, a16, dport);
		}
		return TC_ACT_OK;
	}

	if ((vbyte >> 4) == 6) {
		__u8 nexthdr = 0;
		__u8 a16[16] = {};
		__u32 a4[4];
		__u8 dport[2] = {0, 0};

		if (bpf_skb_load_bytes_relative(skb, 6, &nexthdr, 1, BPF_HDR_START_NET))
			return TC_ACT_OK;
		if (bpf_skb_load_bytes_relative(skb, 24, a16, 16, BPF_HDR_START_NET))
			return TC_ACT_OK;
		__builtin_memcpy(a4, a16, sizeof(a4));

		if (skb_v6_is_loopback(a4))
			return TC_ACT_OK;
		if (skb_v6_is_link_local(a4))
			return TC_ACT_OK;

		if (skb_v6_is_v4mapped(a4)) {
			__be32 v4 = a4[3];

			if (cg_dst_in_ignored(v4))
				return TC_ACT_OK;
			if (cg_dst_is_allowlisted(v4))
				return TC_ACT_OK;
		} else if (skb_v6_is_allowlisted(a16)) {
			return TC_ACT_OK;
		}

		(void)bpf_skb_load_bytes_relative(skb, 40 + 2, dport, 2, BPF_HDR_START_NET);

		if (skb_backstop_recently_seen(a16))
			return TC_ACT_OK;

		skb_emit_backstop(skb, AF_INET6, nexthdr, a16, dport);
		return TC_ACT_OK;
	}

	return TC_ACT_OK;
}
