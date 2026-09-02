//go:build linux

package agent

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestBpfSelfDefenseSourceWiring pins sub-project B's BPF wiring: the lsm/bpf
// self-defense section is included in the combined source before the socket LSM
// section, it is a lsm/bpf program, it propagates a prior LSM denial unchanged,
// dispatches the three self-object cmds, exempts the agent's own tgid, and ships
// inert (the cfg.enabled gate). These are source invariants the verifier work in
// later slices depends on — assert them without a BPF load so they run on any
// Linux arch.
func TestBpfSelfDefenseSourceWiring(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))

	combined, err := os.ReadFile(filepath.Join(root, "bpf", "trace_defend_all.bpf.c"))
	if err != nil {
		t.Fatalf("read combined: %v", err)
	}
	ct := string(combined)
	selfIdx := strings.Index(ct, `#include "trace_lsm_bpf_self_defense.inc"`)
	lsmIdx := strings.Index(ct, `#include "trace_lsm_defend_lsm.inc"`)
	if selfIdx < 0 || lsmIdx < 0 || !(selfIdx < lsmIdx) {
		t.Fatalf("self-defense section must be included before the socket LSM section: self=%d lsm=%d", selfIdx, lsmIdx)
	}
	if !strings.Contains(ct, `#include "bpf_self_defense_event.h"`) {
		t.Error("combined source must include bpf_self_defense_event.h")
	}

	src, err := os.ReadFile(filepath.Join(root, "bpf", "trace_lsm_bpf_self_defense.inc"))
	if err != nil {
		t.Fatalf("read self-defense inc: %v", err)
	}
	st := string(src)

	if !strings.Contains(st, `SEC("lsm/bpf")`) {
		t.Error("self-defense must be a lsm/bpf program")
	}
	// Propagate a prior LSM module's denial rather than overriding it.
	if !strings.Contains(st, "if (ret != 0)") || !strings.Contains(st, "return ret;") {
		t.Error("self-defense must propagate a prior LSM denial (ret != 0 => return ret)")
	}
	// Inert until configured: the cfg.enabled gate must guard the whole hook.
	if !strings.Contains(st, "enabled") || !strings.Contains(st, "selfdef_active_cfg(") {
		t.Error("self-defense must be gated by self_defense_cfg.enabled (selfdef_active_cfg)")
	}
	// Agent self-exemption.
	if !strings.Contains(st, "cfg->agent_tgid") {
		t.Error("self-defense must exempt the agent's own tgid")
	}
	// The four self-object cmds dispatched against the id sets / pin prefix.
	for _, want := range []string{
		"BPF_PROG_GET_FD_BY_ID",
		"BPF_MAP_GET_FD_BY_ID",
		"BPF_LINK_GET_FD_BY_ID",
		"BPF_OBJ_GET",
		"self_prog_ids",
		"self_map_ids",
		"self_link_ids",
		"self_pin_prefix",
	} {
		if !strings.Contains(st, want) {
			t.Errorf("missing expected reference %q", want)
		}
	}
	// Deny is -EPERM; the pin-path user read must be allow-on-error (never block
	// a legitimate open on a failed read).
	if !strings.Contains(st, "return -EPERM;") {
		t.Error("self-defense must deny with -EPERM on a self-object hit")
	}
	if !strings.Contains(st, "bpf_probe_read_user_str(") {
		t.Error("pin-path branch must read attr->pathname via bpf_probe_read_user_str")
	}
}
