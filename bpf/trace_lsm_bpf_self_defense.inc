/*
 * lsm/bpf self-defense section of bpf/trace_defend_all.bpf.c (sub-project B).
 *
 * Goal: stop a malicious build step holding CAP_BPF / CAP_SYS_ADMIN from
 * obtaining a handle to coldstep's OWN bpf programs/maps and then detaching or
 * unloading the monitor (the Doyensec/Datadog "unload the monitor" gap).
 *
 * Scope is "self objects only" — zero blast radius to any other BPF user on the
 * runner. The hook denies exactly three control-plane operations, and ONLY when
 * they target a coldstep object:
 *
 *   BPF_PROG_GET_FD_BY_ID  attr->prog_id ∈ self_prog_ids  → -EPERM
 *   BPF_MAP_GET_FD_BY_ID   attr->map_id  ∈ self_map_ids   → -EPERM
 *   BPF_OBJ_GET            attr->pathname prefix==pin dir  → -EPERM
 *
 * Realistic CAP_BPF attackers have no pre-existing fd to coldstep objects, so
 * these "get a handle" paths are the chokepoint: deny the handle and the
 * follow-on DETACH/DELETE cannot happen. prog_id and map_id overlay the same
 * union offset in bpf_attr, so one CO-RE read serves both id cmds.
 *
 * The agent's own runtime bpf() calls (allowlist BPF_MAP_UPDATE_ELEM, ringbuf
 * consume) act on fds it already holds from load time — they never call
 * *_GET_FD_BY_ID or BPF_OBJ_GET, so they never reach a deny branch. The cfg
 * agent_tgid additionally exempts the agent itself (it may re-open its own pins
 * on resume).
 *
 * Armed by self_defense_cfg.enabled, which Go flips to 1 only AFTER populating
 * the id sets — so there is no window where the hook denies before ids are
 * known. Until then every call returns 0 (allow), i.e. fully inert.
 *
 * The combined .bpf.c provides vmlinux/BPF helpers, LICENSE, EPERM, and the
 * bpf_self_defense_event struct (bpf_self_defense_event.h) before this file.
 */

#ifndef ENOENT
#define ENOENT 2
#endif

#define COLDSTEP_PIN_PREFIX_MAX 64
#define COLDSTEP_SELFDEF_DEDUP_NS 1000000000ULL /* 1s ringbuf-emit cooldown */

struct cs_self_defense_cfg {
	__u32 agent_tgid; /* tgid of the coldstep agent process (exempt) */
	__u8 enabled;     /* 0 until Go has populated the id sets */
	__u8 _pad[3];
};

/* Set membership: coldstep's own prog ids (BPF_OBJ_GET_INFO_BY_FD at load). */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u32);
	__type(value, __u8);
} self_prog_ids SEC(".maps");

/* Set membership: coldstep's own map ids. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u32);
	__type(value, __u8);
} self_map_ids SEC(".maps");

/* The agent's bpffs pin directory prefix (NUL-terminated). Empty string (first
 * byte 0) disables the BPF_OBJ_GET branch entirely. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, char[COLDSTEP_PIN_PREFIX_MAX]);
} self_pin_prefix SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct cs_self_defense_cfg);
} self_defense_cfg SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 12); /* 4 KiB; tamper attempts are low volume */
} bpf_self_defense_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} bpf_self_defense_reserve_failures SEC(".maps");

/* Dedup ringbuf emits: key = ((u64)cmd << 32) | target_id, value = last ts. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 256);
	__type(key, __u64);
	__type(value, __u64);
} self_defense_seen SEC(".maps");

static __always_inline void selfdef_note_reserve_failed(void)
{
	__u32 k = 0;
	/* AUDIT(5a): null checked — only used inside `if (v)`. */
	__u32 *v = bpf_map_lookup_elem(&bpf_self_defense_reserve_failures, &k);
	if (v)
		__sync_fetch_and_add(v, 1);
}

/* Returns true if a ringbuf emit for (cmd,id) should be suppressed because one
 * was emitted within the last COLDSTEP_SELFDEF_DEDUP_NS. Always lets the FIRST
 * sighting through. Deny still happens regardless — this only rate-limits the
 * emit so a retry loop is not a ringbuf storm. */
static __always_inline bool selfdef_dedup(__s32 cmd, __u32 id, __u64 now)
{
	__u64 key = ((__u64)(__u32)cmd << 32) | (__u64)id;
	/* AUDIT(5a): null checked. */
	__u64 *last = bpf_map_lookup_elem(&self_defense_seen, &key);
	if (last && (now - *last) < COLDSTEP_SELFDEF_DEDUP_NS)
		return true;
	bpf_map_update_elem(&self_defense_seen, &key, &now, BPF_ANY);
	return false;
}

static __always_inline void selfdef_emit(__s32 cmd, __u32 id, __u8 kind)
{
	__u64 now = bpf_ktime_get_ns();
	if (selfdef_dedup(cmd, id, now))
		return;

	/* AUDIT(5b): submit/discard paired — only exit between reserve and submit
	 * is the `!ev` early return (no slot held). Submit unconditional after. */
	struct bpf_self_defense_event *ev =
		bpf_ringbuf_reserve(&bpf_self_defense_events, sizeof(*ev), 0);
	if (!ev) {
		selfdef_note_reserve_failed();
		return;
	}
	ev->ts = now;
	bpf_get_current_comm(&ev->comm, sizeof(ev->comm));
	ev->tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
	ev->target_id = id;
	ev->cmd = cmd;
	ev->target_kind = kind;
	ev->_pad[0] = 0;
	ev->_pad[1] = 0;
	ev->_pad[2] = 0;
	bpf_ringbuf_submit(ev, 0);
}

/* Reads the cfg; returns NULL when the hook is disabled or cfg is missing. */
static __always_inline struct cs_self_defense_cfg *selfdef_active_cfg(void)
{
	__u32 k = 0;
	/* AUDIT(5a): null checked by caller. */
	struct cs_self_defense_cfg *cfg = bpf_map_lookup_elem(&self_defense_cfg, &k);
	if (!cfg || !cfg->enabled)
		return NULL;
	return cfg;
}

/*
 * lsm/bpf hook. The trailing `int ret` carries the cumulative LSM result; if a
 * prior module already denied (ret != 0) we propagate it unchanged rather than
 * override. Returns 0 to allow, -EPERM to deny.
 */
SEC("lsm/bpf")
int BPF_PROG(coldstep_bpf_self_defense, int cmd, union bpf_attr *attr,
	     unsigned int size, int ret)
{
	if (ret != 0)
		return ret;

	struct cs_self_defense_cfg *cfg = selfdef_active_cfg();
	if (!cfg)
		return 0;
	if (!attr)
		return 0;

	__u32 self_tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
	if (self_tgid == cfg->agent_tgid)
		return 0; /* the agent itself may re-open its own objects */

	if (cmd == BPF_PROG_GET_FD_BY_ID) {
		/* prog_id and map_id overlay the same union offset. */
		__u32 id = BPF_CORE_READ(attr, prog_id);
		__u8 *hit = bpf_map_lookup_elem(&self_prog_ids, &id); /* AUDIT(5a) */
		if (hit) {
			selfdef_emit(cmd, id, COLDSTEP_SELFDEF_KIND_PROG);
			return -EPERM;
		}
		return 0;
	}

	if (cmd == BPF_MAP_GET_FD_BY_ID) {
		__u32 id = BPF_CORE_READ(attr, map_id);
		__u8 *hit = bpf_map_lookup_elem(&self_map_ids, &id); /* AUDIT(5a) */
		if (hit) {
			selfdef_emit(cmd, id, COLDSTEP_SELFDEF_KIND_MAP);
			return -EPERM;
		}
		return 0;
	}

	if (cmd == BPF_OBJ_GET) {
		__u32 k = 0;
		/* AUDIT(5a): null checked. */
		char *prefix = bpf_map_lookup_elem(&self_pin_prefix, &k);
		if (!prefix || prefix[0] == '\0')
			return 0; /* pin protection disabled */

		__u64 uptr = BPF_CORE_READ(attr, pathname);
		char path[COLDSTEP_PIN_PREFIX_MAX] = {};
		/* AUDIT(5f): allow-on-error — a failed user read must NOT block a
		 * legitimate open, so we fall through to allow when the read fails. */
		long n = bpf_probe_read_user_str(&path, sizeof(path), (const void *)uptr);
		if (n <= 0)
			return 0;

		/* Bounded prefix compare against the configured pin dir. */
		bool match = true;
#pragma unroll
		for (int i = 0; i < COLDSTEP_PIN_PREFIX_MAX; i++) {
			char pc = prefix[i];
			if (pc == '\0')
				break; /* end of prefix => full prefix matched so far */
			if (path[i] != pc) {
				match = false;
				break;
			}
		}
		if (match) {
			selfdef_emit(cmd, 0, COLDSTEP_SELFDEF_KIND_PIN);
			return -EPERM;
		}
		return 0;
	}

	return 0;
}
