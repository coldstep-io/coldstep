#ifndef COLDSTEP_BPF_SELF_DEFENSE_EVENT_H
#define COLDSTEP_BPF_SELF_DEFENSE_EVENT_H

/*
 * Wire struct for the lsm/bpf self-defense hook (sub-project B).
 *
 * Emitted once (deduped) when a non-agent task attempts to obtain a handle to
 * one of coldstep's own BPF objects via BPF_PROG_GET_FD_BY_ID /
 * BPF_MAP_GET_FD_BY_ID / BPF_LINK_GET_FD_BY_ID (by id) or BPF_OBJ_GET (by pin
 * path), and the hook denies it with -EPERM. target_kind distinguishes
 * prog / map / link / pin so the digest can attribute the attempt. The JSONL
 * seq is NOT carried on the wire — userspace allocates it under jsonlMu on
 * emit (BG-1 pattern).
 *
 * Fixed 40-byte layout — keep in sync with bpfSelfDefenseEventWireSize in
 * internal/agent/agent_linux.go and the Go decoder:
 *   ts u64 (8) + comm[16] (16) + tgid u32 (4) + target_id u32 (4)
 *   + cmd s32 (4) + target_kind u8 (1) + _pad[3] (3) = 40, naturally aligned.
 */

#define COLDSTEP_SELFDEF_KIND_PROG 1
#define COLDSTEP_SELFDEF_KIND_MAP 2
#define COLDSTEP_SELFDEF_KIND_PIN 3
#define COLDSTEP_SELFDEF_KIND_LINK 4

struct bpf_self_defense_event {
	__u64 ts;          /* bpf_ktime_get_ns() at deny */
	char comm[16];     /* offending task comm (best-effort) */
	__u32 tgid;        /* offending task tgid */
	__u32 target_id;   /* prog_id / map_id; 0 for pin-path opens */
	__s32 cmd;         /* the denied bpf() cmd */
	__u8 target_kind;  /* COLDSTEP_SELFDEF_KIND_* */
	__u8 _pad[3];
};

_Static_assert(sizeof(struct bpf_self_defense_event) == 40,
	       "bpf_self_defense_event wire size mismatch");

#endif /* COLDSTEP_BPF_SELF_DEFENSE_EVENT_H */
