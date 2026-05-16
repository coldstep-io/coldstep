/*
 * Shared IPv4 enforce policy + deny ringbuf emit for cgroup and LSM objects.
 *
 * Before #include, each translation unit must define map symbol macros (bare
 * identifiers, no string):
 *   CS_EF_RB_DENY           — BPF_MAP_TYPE_RINGBUF (struct deny_event samples)
 *   CS_EF_PC_DENY_FAIL      — BPF_MAP_TYPE_PERCPU_ARRAY failure counter
 *   CS_EF_ARR_ENFORCE_CFG   — mode array (COLDSTEP_ENFORCE_*)
 *   CS_EF_TRIE_ALLOWED      — LPM trie allowlist
 *   CS_EF_TRIE_IGNORED      — LPM trie ignored CIDRs
 *
 * Caller must #include "enforce_lpm_key.h" before BPF map defs that use
 * struct ns_lpm4_key, then #include "dns_cache.h" (dns_cache + allowed_domains maps).
 * Caller must define IPPROTO_*, AF_INET, COLDSTEP_ENFORCE_KEY_MODE, *_MODE_*,
 * COLDSTEP_PROTO_*, COLDSTEP_DENY_REASON_* to match existing enforce programs.
 */
#ifndef COLDSTEP_ENFORCE_POLICY_INC
#define COLDSTEP_ENFORCE_POLICY_INC

#ifndef CS_EF_RB_DENY
#error "Define CS_EF_RB_DENY before enforce_policy.inc"
#endif
#ifndef CS_EF_PC_DENY_FAIL
#error "Define CS_EF_PC_DENY_FAIL before enforce_policy.inc"
#endif
#ifndef CS_EF_ARR_ENFORCE_CFG
#error "Define CS_EF_ARR_ENFORCE_CFG before enforce_policy.inc"
#endif
#ifndef CS_EF_TRIE_ALLOWED
#error "Define CS_EF_TRIE_ALLOWED before enforce_policy.inc"
#endif
#ifndef CS_EF_TRIE_IGNORED
#error "Define CS_EF_TRIE_IGNORED before enforce_policy.inc"
#endif

static __always_inline int enforcement_enabled(void)
{
	__u32 key = COLDSTEP_ENFORCE_KEY_MODE;
	__u32 *mode = bpf_map_lookup_elem(&CS_EF_ARR_ENFORCE_CFG, &key);

	return mode && *mode == COLDSTEP_ENFORCE_MODE_ENFORCE;
}

static __always_inline int dst_is_allowlisted(__be32 addr)
{
	struct ns_lpm4_key k = {};

	k.prefixlen = 32;
	k.addr = addr;
	__u8 *ok = bpf_map_lookup_elem(&CS_EF_TRIE_ALLOWED, &k);
	if (ok)
		return 1;

	char *domain = bpf_map_lookup_elem(&dns_cache, &addr);
	if (domain) {
		__u8 *dom_ok = bpf_map_lookup_elem(&allowed_domains, domain);
		if (dom_ok)
			return 1;
	}

	return 0;
}

static __always_inline int dst_in_ignored(__be32 daddr)
{
	struct ns_lpm4_key k = {};

	k.prefixlen = 32;
	k.addr = daddr;
	__u8 *v = bpf_map_lookup_elem(&CS_EF_TRIE_IGNORED, &k);

	return v != 0;
}

static __always_inline void note_deny_ring_reserve_failed(void)
{
	__u32 k = 0;
	__u32 *v = bpf_map_lookup_elem(&CS_EF_PC_DENY_FAIL, &k);

	if (!v)
		return;
	(*v)++;
}

static __always_inline void emit_deny_event_ipv4(__u8 protocol, const __u8 *dst4, __be16 dport, __u8 reason)
{
	struct deny_event *de = bpf_ringbuf_reserve(&CS_EF_RB_DENY, sizeof(*de), 0);

	if (!de) {
		note_deny_ring_reserve_failed();
		return;
	}
	{
		__u64 pt = bpf_get_current_pid_tgid();

		de->tgid = (__u32)(pt >> 32);
		de->tid = (__u32)pt;
	}
	bpf_get_current_comm(&de->comm, sizeof(de->comm));
	de->protocol = protocol;
	de->reason = reason;
	de->af = AF_INET;
	de->_pad = 0;
	__builtin_memset(de->daddr, 0, sizeof(de->daddr));
	if (dst4)
		__builtin_memcpy(de->daddr, dst4, 4);
	__builtin_memcpy(de->dport, &dport, sizeof(de->dport));
	bpf_ringbuf_submit(de, 0);
}

#endif /* COLDSTEP_ENFORCE_POLICY_INC */
