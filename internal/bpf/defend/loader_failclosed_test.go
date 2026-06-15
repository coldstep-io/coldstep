//go:build linux

package defend

import (
	"testing"

	"github.com/cilium/ebpf"
)

// TestIPv6EnforcementSymbolsInSpec asserts that the three IPv6 enforcement
// primitives required by LoadDefendObjectsForKernel since H14 (v0.4.0) are
// always present in the embedded CollectionSpec produced by LoadDefend().
//
// Because the loader now calls detachProgram / detachMap (fail-closed) rather
// than detachProgramIfPresent / detachMapIfPresent, a missing symbol causes
// LoadDefendObjectsForKernel to return an error instead of silently continuing
// with an unattached program/map. This test guards against a stale or
// accidentally trimmed embedded ELF — a missing symbol here means the
// regeneration step (go generate ./internal/bpf/defend/) did not run or the
// source bpf/trace_defend_cgroup.inc was changed incompatibly.
//
// Pure spec parse via cilium/ebpf — no kernel attach needed; runs on any
// Linux arch covered by the generated _bpfel.go build constraints.
func TestIPv6EnforcementSymbolsInSpec(t *testing.T) {
	spec, err := LoadDefend()
	if err != nil {
		t.Fatalf("LoadDefend: %v", err)
	}

	for _, name := range []string{"defend_cgroup_connect6", "defend_cgroup_sendmsg6"} {
		if _, ok := spec.Programs[name]; !ok {
			t.Errorf("IPv6 enforcement program %q missing from CollectionSpec; "+
				"LoadDefendObjectsForKernel will now fail-closed on absence — "+
				"regenerate BPF objects via go generate ./internal/bpf/defend/", name)
		}
	}

	// allowed_ipv6 (H14 enforcement) plus the cgroup IPv6 observe-only counters
	// are all required fail-closed by LoadDefendObjectsForKernel — they are
	// unconditionally compiled into the cgroup section, which is never stripped.
	for _, name := range []string{"allowed_ipv6", "ipv6_connect_observed", "ipv6_sendmsg_observed"} {
		if _, ok := spec.Maps[name]; !ok {
			t.Errorf("required cgroup IPv6 map %q missing from CollectionSpec; "+
				"LoadDefendObjectsForKernel will now fail-closed on absence — "+
				"regenerate BPF objects via go generate ./internal/bpf/defend/", name)
		}
	}
}

// TestDetachProgramFailsOnAbsence verifies that detachProgram returns a
// non-nil error when the named program is not in the collection, confirming
// the fail-closed primitive behaves correctly. This is the same helper called
// by the cgIPv6Programs loop in LoadDefendObjectsForKernel.
//
// We construct a fake *ebpf.Collection with Programs populated from the parsed
// spec (minus the target name) — no kernel load required, since detachProgram
// only inspects the Programs map.
func TestDetachProgramFailsOnAbsence(t *testing.T) {
	spec, err := LoadDefend()
	if err != nil {
		t.Fatalf("LoadDefend: %v", err)
	}

	// Remove the target program from the spec before building the fake
	// collection so that defend_cgroup_connect6 is absent.
	delete(spec.Programs, "defend_cgroup_connect6")

	// Build a kernel-free fake collection: populate Programs from spec keys
	// (values are nil *ebpf.Program — detachProgram only checks key presence).
	progs := make(map[string]*ebpf.Program, len(spec.Programs))
	for k := range spec.Programs {
		progs[k] = nil
	}
	fakeColl := &ebpf.Collection{Programs: progs}

	var dst *ebpf.Program
	if err := detachProgram(fakeColl, "defend_cgroup_connect6", &dst); err == nil {
		t.Fatal("detachProgram on absent program returned nil error; want fail-closed error")
	}
}

// TestDetachMapFailsOnAbsence verifies that detachMap returns a non-nil error
// when the named map is not in the collection, confirming the fail-closed
// primitive used for allowed_ipv6 behaves correctly.
func TestDetachMapFailsOnAbsence(t *testing.T) {
	spec, err := LoadDefend()
	if err != nil {
		t.Fatalf("LoadDefend: %v", err)
	}

	// Remove the target map from the spec before building the fake collection.
	delete(spec.Maps, "allowed_ipv6")

	maps := make(map[string]*ebpf.Map, len(spec.Maps))
	for k := range spec.Maps {
		maps[k] = nil
	}
	fakeColl := &ebpf.Collection{Maps: maps}

	var dst *ebpf.Map
	if err := detachMap(fakeColl, "allowed_ipv6", &dst); err == nil {
		t.Fatal("detachMap on absent map returned nil error; want fail-closed error")
	}
}
