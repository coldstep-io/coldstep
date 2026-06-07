//go:build integration && linux && !windows

// Sub-project B (lsm/bpf self-defense) integration tests. Two layers:
//
//   - TestBpfSelfDefense_ArmPopulatesIDs runs anywhere CONFIG_BPF_LSM is
//     compiled in (GH ubuntu-latest qualifies): it loads the defend objects,
//     arms the hook, and asserts the Go-side population path recorded the
//     agent's own object ids + flipped enabled=1. No attach / enforcement
//     needed, so it gives real CI signal.
//
//   - TestRedTeam_BpfSelfDefense_DeniesSelfObjectHandle exercises the actual
//     deny path end-to-end. It is gated on "bpf" being in the kernel's boot
//     lsm= chain (/sys/kernel/security/lsm) because LSM hooks only ENFORCE
//     there — GH hosted runners and WSL boot without bpf in the chain, so the
//     hook attaches but stays silent (same surface as the existing
//     lsm/socket_connect deny). On those hosts the test skips: a genuine
//     environment-capability gate, not a stubbed-out feature.

package agent

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"

	"github.com/coldstep-io/coldstep/internal/bpf/defend"
)

// bpfInLSMChain reports whether "bpf" is in the kernel's active LSM list, i.e.
// BPF LSM hooks will actually enforce (not silently no-op).
func bpfInLSMChain(t *testing.T) bool {
	t.Helper()
	b, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		return false
	}
	for _, p := range strings.Split(strings.TrimSpace(string(b)), ",") {
		if p == "bpf" {
			return true
		}
	}
	return false
}

// loadDefendForSelfDefenseTest loads the defend objects with the LSM section,
// skipping the test when CONFIG_BPF_LSM is unavailable (the section is stripped
// / falls back) so the self-defense program is absent.
func loadDefendForSelfDefenseTest(t *testing.T) *defend.DefendObjects {
	t.Helper()
	objs := &defend.DefendObjects{}
	res, err := defend.LoadDefendObjectsForKernel(objs, true, defend.HaveIOUringLSM())
	if err != nil {
		t.Fatalf("load defend objects: %v", err)
	}
	if res.LSMFellBack || objs.ColdstepBpfSelfDefense == nil || objs.SelfDefenseCfg == nil {
		_ = objs.Close()
		t.Skip("CONFIG_BPF_LSM unavailable: self-defense program/maps not loaded")
	}
	return objs
}

func TestBpfSelfDefense_ArmPopulatesIDs(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root for BPF load")
	}
	objs := loadDefendForSelfDefenseTest(t)
	defer objs.Close()

	const wantTGID = uint32(424242)
	progN, mapN := armBpfSelfDefense(objs, wantTGID)
	if progN == 0 || mapN == 0 {
		t.Fatalf("armBpfSelfDefense recorded progN=%d mapN=%d; want both > 0", progN, mapN)
	}

	// cfg armed: enabled=1, agent_tgid set.
	var cfg selfDefenseCfgValue
	if err := objs.SelfDefenseCfg.Lookup(uint32(0), &cfg); err != nil {
		t.Fatalf("lookup self_defense_cfg: %v", err)
	}
	if cfg.Enabled != 1 || cfg.AgentTGID != wantTGID {
		t.Fatalf("cfg=%+v want Enabled=1 AgentTGID=%d", cfg, wantTGID)
	}

	// A real defend program id must be in self_prog_ids.
	if info, err := objs.DefendConnect4.Info(); err == nil {
		if id, ok := info.ID(); ok {
			var v uint8
			if err := objs.SelfProgIds.Lookup(uint32(id), &v); err != nil {
				t.Fatalf("defend_connect4 id %d not protected in self_prog_ids: %v", id, err)
			}
		}
	}
	// A real defend map id must be in self_map_ids.
	if info, err := objs.DefendCfg.Info(); err == nil {
		if id, ok := info.ID(); ok {
			var v uint8
			if err := objs.SelfMapIds.Lookup(uint32(id), &v); err != nil {
				t.Fatalf("defend_cfg map id %d not protected in self_map_ids: %v", id, err)
			}
		}
	}
}

func TestRedTeam_BpfSelfDefense_DeniesSelfObjectHandle(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root for BPF load")
	}
	if !bpfInLSMChain(t) {
		t.Skip("bpf not in kernel lsm= chain: LSM hooks attach but do not enforce on this host (GH hosted runners / WSL)")
	}
	objs := loadDefendForSelfDefenseTest(t)
	defer objs.Close()

	lnk, err := link.AttachLSM(link.LSMOptions{Program: objs.ColdstepBpfSelfDefense})
	if err != nil {
		t.Skipf("lsm/bpf attach unsupported on this host: %v", err)
	}
	defer lnk.Close()

	newMap := func() *ebpf.Map {
		m, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Array, KeySize: 4, ValueSize: 4, MaxEntries: 1})
		if err != nil {
			t.Fatalf("create throwaway map: %v", err)
		}
		return m
	}
	idOf := func(m *ebpf.Map) ebpf.MapID {
		info, err := m.Info()
		if err != nil {
			t.Fatalf("map info: %v", err)
		}
		id, ok := info.ID()
		if !ok {
			t.Fatalf("map has no id")
		}
		return id
	}

	protected := newMap()
	defer protected.Close()
	control := newMap()
	defer control.Close()
	protectedID := idOf(protected)
	controlID := idOf(control)

	// Arm: protect only `protected`, and set a bogus agent_tgid so THIS test
	// process is not exempt (the in-process agent harness would otherwise be
	// the agent itself).
	if err := objs.SelfMapIds.Put(uint32(protectedID), uint8(1)); err != nil {
		t.Fatalf("put protected id: %v", err)
	}
	cfg := selfDefenseCfgValue{AgentTGID: 0xFFFFFFFE, Enabled: 1}
	if err := objs.SelfDefenseCfg.Put(uint32(0), cfg); err != nil {
		t.Fatalf("put cfg: %v", err)
	}

	rd, err := ringbuf.NewReader(objs.BpfSelfDefenseEvents)
	if err != nil {
		t.Fatalf("ringbuf reader: %v", err)
	}
	defer rd.Close()

	// Deny: grabbing a handle to the protected id must fail with EPERM.
	if m, err := ebpf.NewMapFromID(protectedID); err == nil {
		_ = m.Close()
		t.Fatalf("expected EPERM grabbing protected map id %d, got a handle", protectedID)
	} else if !errors.Is(err, unix.EPERM) {
		t.Fatalf("expected EPERM for protected id, got %v", err)
	}

	// No false positive: a non-coldstep id is allowed (zero blast radius).
	if m, err := ebpf.NewMapFromID(controlID); err != nil {
		t.Fatalf("control map id %d must be allowed, got %v", controlID, err)
	} else {
		_ = m.Close()
	}

	// The deny must have emitted exactly one self-defense event for the id.
	rd.SetDeadline(time.Now().Add(2 * time.Second))
	rec, err := rd.Read()
	if err != nil {
		t.Fatalf("expected a bpf_self_defense event: %v", err)
	}
	_, _, _, targetID, _, kind, ok := decodeBpfSelfDefenseEvent(rec.RawSample)
	if !ok || targetID != uint32(protectedID) || kind != 2 /* KIND_MAP */ {
		t.Fatalf("event targetID=%d kind=%d ok=%v; want id=%d kind=2(map)", targetID, kind, ok, protectedID)
	}
}
