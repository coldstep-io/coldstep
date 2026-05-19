/*
 * Shared IPv4 defend policy + deny ringbuf emit for cgroup and LSM hook
 * sections of bpf/trace_defend_all.bpf.c.
 *
 * Intentionally NOT include-guarded: this file is included twice in the
 * combined defend translation unit (once for the cgroup section with cg_*
 * map names, once for the LSM section with lsm_* map names). Each include
 * defines a distinct set of static __always_inline helpers whose names are
 * disambiguated by macro substitution from the caller.
 *
 * Before #include, each section must define map symbol macros (bare
 * identifiers, no string):
 *   CS_DEF_RB_DENY          — BPF_MAP_TYPE_RINGBUF (struct deny_event samples)
 *   CS_DEF_PC_DENY_FAIL     — BPF_MAP_TYPE_PERCPU_ARRAY failure counter
 *   CS_DEF_ARR_DEFEND_CFG   — mode array (COLDSTEP_DEFEND_*)
 *   CS_DEF_TRIE_ALLOWED     — LPM trie allowlist
 *   CS_DEF_TRIE_IGNORED     — LPM trie ignored CIDRs
 *
 * The section must also rename the helper functions via `#define` so the
 * other section can declare its own copies in the same TU without
 * colliding (e.g. `#define defense_enabled cg_defense_enabled`). #undef
 * after the include.
 *
 * Caller must #include "defend_lpm_key.h" before BPF map defs that use
 * struct ns_lpm4_key, then #include "dns_cache.h" (dns_cache + allowed_domains maps).
 * Caller must define IPPROTO_*, AF_INET, COLDSTEP_DEFEND_KEY_MODE, *_MODE_*,
 * COLDSTEP_PROTO_*, COLDSTEP_DENY_REASON_* to match existing defend programs.
 */

#ifndef CS_DEF_RB_DENY
#error "Define CS_DEF_RB_DENY before defend_policy.inc"
#endif
#ifndef CS_DEF_PC_DENY_FAIL
#error "Define CS_DEF_PC_DENY_FAIL before defend_policy.inc"
#endif
#ifndef CS_DEF_ARR_DEFEND_CFG
#error "Define CS_DEF_ARR_DEFEND_CFG before defend_policy.inc"
#endif
#ifndef CS_DEF_TRIE_ALLOWED
#error "Define CS_DEF_TRIE_ALLOWED before defend_policy.inc"
#endif
#ifndef CS_DEF_TRIE_IGNORED
#error "Define CS_DEF_TRIE_IGNORED before defend_policy.inc"
#endif

static __always_inline int defense_enabled(void)
{
	__u32 key = COLDSTEP_DEFEND_KEY_MODE;
	/* AUDIT(5a): null checked — `mode &&` guards deref below. */
	__u32 *mode = bpf_map_lookup_elem(&CS_DEF_ARR_DEFEND_CFG, &key);

	return mode && *mode == COLDSTEP_DEFEND_MODE_DEFEND;
}

static __always_inline int dst_is_allowlisted(__be32 addr)
{
	struct ns_lpm4_key k = {};

	k.prefixlen = 32;
	k.addr = addr;
	/* AUDIT(5a): null checked — only used inside `if (ok)`. */
	__u8 *ok = bpf_map_lookup_elem(&CS_DEF_TRIE_ALLOWED, &k);
	if (ok)
		return 1;

	/* AUDIT(5a): null checked — `if (domain)` guards downstream lookup. */
	char *domain = bpf_map_lookup_elem(&dns_cache, &addr);
	if (domain) {
		/* AUDIT(5a): null checked — only used inside `if (dom_ok)`. */
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
	/* AUDIT(5a): null checked — pointer used only as boolean (`v != 0`). */
	__u8 *v = bpf_map_lookup_elem(&CS_DEF_TRIE_IGNORED, &k);

	return v != 0;
}

static __always_inline void note_deny_ring_reserve_failed(void)
{
	__u32 k = 0;
	/* AUDIT(5a): null checked — early return guards `(*v)++`. */
	__u32 *v = bpf_map_lookup_elem(&CS_DEF_PC_DENY_FAIL, &k);

	if (!v)
		return;
	(*v)++;
}

static __always_inline void emit_deny_event_ipv4(__u8 protocol, const __u8 *dst4, __be16 dport, __u8 reason)
{
	/* AUDIT(5b): submit/discard paired — only exit path between reserve and
	 * submit is the `!de` early return (no slot held). Submit at end. */
	struct deny_event *de = bpf_ringbuf_reserve(&CS_DEF_RB_DENY, sizeof(*de), 0);

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
