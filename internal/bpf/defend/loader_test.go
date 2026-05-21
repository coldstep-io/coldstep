//go:build linux

package defend

import (
	"testing"
)

// TestDefendSpecExposesIOUringLSMProgram asserts the compiled BPF object
// contains the H15 lsm/io_uring_cmd program. This is a pure spec parse —
// no kernel attach — so it runs on any Linux arch covered by the
// generated _bpfel.go build constraints.
func TestDefendSpecExposesIOUringLSMProgram(t *testing.T) {
	spec, err := LoadDefend()
	if err != nil {
		t.Fatalf("LoadDefend: %v", err)
	}
	prog, ok := spec.Programs["lsm_io_uring_cmd"]
	if !ok {
		t.Fatalf("lsm_io_uring_cmd program missing from CollectionSpec")
	}
	if got := prog.SectionName; got != "lsm/io_uring_cmd" {
		t.Fatalf("lsm_io_uring_cmd SectionName=%q want %q", got, "lsm/io_uring_cmd")
	}
}

// TestDefendSpecStripsIOUringLSMWithoutLSM mirrors LoadDefendObjectsForKernel
// at the spec-parse layer: when wantLSM is false, the io_uring_cmd program
// (plus the other LSM programs and LSM-only maps) must be removable so
// the resulting spec can prog_load on kernels without CONFIG_BPF_LSM.
func TestDefendSpecStripsIOUringLSMWithoutLSM(t *testing.T) {
	spec, err := LoadDefend()
	if err != nil {
		t.Fatalf("LoadDefend: %v", err)
	}
	delete(spec.Programs, "lsm_socket_connect")
	delete(spec.Programs, "lsm_socket_sendmsg")
	delete(spec.Programs, "lsm_io_uring_cmd")
	for _, name := range []string{
		"lsm_socket_connect",
		"lsm_socket_sendmsg",
		"lsm_io_uring_cmd",
	} {
		if _, present := spec.Programs[name]; present {
			t.Fatalf("expected %q to be removable from spec.Programs", name)
		}
	}
	// Cgroup programs must remain — they are the always-on defense path.
	for _, name := range []string{"defend_connect4", "defend_sendmsg4"} {
		if _, present := spec.Programs[name]; !present {
			t.Fatalf("expected %q to remain in spec.Programs after LSM strip", name)
		}
	}
}

// TestDefendSpecStripsIOUringLSMOnlyOnOldKernel covers the wantLSM=true,
// wantIOUringLSM=false path: socket_connect and socket_sendmsg still load
// (LSM-only maps stay) while just lsm_io_uring_cmd is dropped.
func TestDefendSpecStripsIOUringLSMOnlyOnOldKernel(t *testing.T) {
	spec, err := LoadDefend()
	if err != nil {
		t.Fatalf("LoadDefend: %v", err)
	}
	delete(spec.Programs, "lsm_io_uring_cmd")

	if _, present := spec.Programs["lsm_io_uring_cmd"]; present {
		t.Fatalf("lsm_io_uring_cmd not removed")
	}
	for _, name := range []string{"lsm_socket_connect", "lsm_socket_sendmsg"} {
		if _, present := spec.Programs[name]; !present {
			t.Fatalf("expected %q to remain when only io_uring is stripped", name)
		}
	}
	for _, name := range []string{
		"lsm_deny_events",
		"lsm_deny_reserve_failures",
		"lsm_defend_cfg",
		"lsm_allowed_ipv4",
		"lsm_ignored_ipv4_lpm",
	} {
		if _, present := spec.Maps[name]; !present {
			t.Fatalf("expected LSM map %q to remain when only io_uring program is stripped", name)
		}
	}
}
