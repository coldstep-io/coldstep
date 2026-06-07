//go:build linux

package agent

import (
	"github.com/cilium/ebpf"

	"github.com/coldstep-io/coldstep/internal/bpf/defend"
)

// selfDefenseCfgValue mirrors struct cs_self_defense_cfg in
// bpf/trace_lsm_bpf_self_defense.inc: agent_tgid u32 + enabled u8 + _pad[3].
type selfDefenseCfgValue struct {
	AgentTGID uint32
	Enabled   uint8
	_         [3]uint8
}

// armBpfSelfDefense (sub-project B) records the kernel ids of coldstep's own
// loaded defend programs/maps into self_prog_ids / self_map_ids, then flips
// self_defense_cfg.enabled to 1 LAST — so the lsm/bpf hook stays inert until
// the protected-id sets are complete (no arm-before-known-ids window).
//
// Best-effort: a missing map (stub predating the section, or LSM stripped)
// makes this a no-op rather than an error — the program ships inert in that
// case. self_pin_prefix is left empty because coldstep does not pin its
// objects today; that disables the BPF_OBJ_GET branch, leaving the by-id
// protection (the realistic CAP_BPF tamper vector) as the active path.
//
// Returns the number of program ids and map ids successfully recorded so the
// caller can surface it in a BPFStatus row.
func armBpfSelfDefense(objs *defend.DefendObjects, agentTGID uint32) (progN, mapN int) {
	if objs.SelfDefenseCfg == nil {
		return 0, 0 // section absent — nothing to arm
	}

	one := uint8(1)
	if objs.SelfProgIds != nil {
		for _, p := range selfDefenseProgramSet(objs) {
			if p == nil {
				continue
			}
			info, err := p.Info()
			if err != nil {
				continue
			}
			id, ok := info.ID()
			if !ok {
				continue
			}
			if err := objs.SelfProgIds.Put(uint32(id), one); err == nil {
				progN++
			}
		}
	}
	if objs.SelfMapIds != nil {
		for _, m := range selfDefenseMapSet(objs) {
			if m == nil {
				continue
			}
			info, err := m.Info()
			if err != nil {
				continue
			}
			id, ok := info.ID()
			if !ok {
				continue
			}
			if err := objs.SelfMapIds.Put(uint32(id), one); err == nil {
				mapN++
			}
		}
	}

	// Arm last: enabled=1 only after the id sets are populated.
	cfg := selfDefenseCfgValue{AgentTGID: agentTGID, Enabled: 1}
	_ = objs.SelfDefenseCfg.Put(uint32(0), cfg)
	return progN, mapN
}

// selfDefenseProgramSet lists every defend program whose handle should be
// protected. Explicit (not reflection) because the generated DefendObjects
// embeds unexported structs, and reflect cannot read promoted exported fields
// through an unexported embed without panicking. nil entries (stripped LSM
// section, older stub) are skipped by the caller.
func selfDefenseProgramSet(o *defend.DefendObjects) []*ebpf.Program {
	return []*ebpf.Program{
		o.DefendConnect4,
		o.DefendSendmsg4,
		o.DefendCgroupConnect6,
		o.DefendCgroupSendmsg6,
		o.DefendSkbEgress,
		o.LsmSocketConnect,
		o.LsmSocketSendmsg,
		o.LsmSocketSendpage,
		o.LsmIoUringCmd,
		o.ColdstepBpfSelfDefense,
	}
}

// selfDefenseMapSet lists every defend map whose handle should be protected,
// including the self-defense maps themselves (so an attacker cannot grab a
// handle to self_defense_cfg and disarm the hook). nil entries are skipped.
func selfDefenseMapSet(o *defend.DefendObjects) []*ebpf.Map {
	return []*ebpf.Map{
		o.DenyEvents,
		o.DenyReserveFailures,
		o.DefendCfg,
		o.AllowedIpv4,
		o.IgnoredIpv4Lpm,
		o.AllowedDomains,
		o.DnsCache,
		o.Ipv6ConnectObserved,
		o.Ipv6SendmsgObserved,
		o.AllowedIpv6,
		o.SkbBackstopEvents,
		o.SkbBackstopReserveFailures,
		o.SkbBackstopSeen,
		o.LsmDenyEvents,
		o.LsmDenyReserveFailures,
		o.LsmDefendCfg,
		o.LsmAllowedIpv4,
		o.LsmIgnoredIpv4Lpm,
		o.SendpageObserved,
		o.SelfProgIds,
		o.SelfMapIds,
		o.SelfPinPrefix,
		o.SelfDefenseCfg,
		o.BpfSelfDefenseEvents,
		o.BpfSelfDefenseReserveFailures,
		o.SelfDefenseSeen,
	}
}
