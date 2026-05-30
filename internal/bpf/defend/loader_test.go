//go:build linux

package defend

import (
	"errors"
	"fmt"
	"testing"

	"github.com/cilium/ebpf/btf"
)

// TestIsSendpageLoadFailure pins the two-signal contract: the error must name
// the sendpage program AND be a recognized structured load failure (btf
// not-found or verifier error). An unrelated error containing the substring,
// or a sendpage btf.ErrNotFound without the name, must not trigger the strip.
func TestIsSendpageLoadFailure(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{
			"sendpage btf not found (kernel 6.5+ removal)",
			fmt.Errorf("program lsm_socket_sendpage: %w", btf.ErrNotFound),
			true,
		},
		{
			"unrelated btf not found without sendpage name",
			fmt.Errorf("program lsm_socket_connect: %w", btf.ErrNotFound),
			false,
		},
		{
			"sendpage substring but not a structured load failure",
			errors.New("write deny event for socket_sendpage: disk full"),
			false,
		},
		{
			"sendpage name plus btf not found in a deeper wrap",
			fmt.Errorf("load defend: %w", fmt.Errorf("program lsm_socket_sendpage: %w", btf.ErrNotFound)),
			true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isSendpageLoadFailure(tc.err); got != tc.want {
				t.Fatalf("isSendpageLoadFailure(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

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

// TestStripAllLSM verifies the shared helper used by both the wantLSM=false
// initial path and the wantLSM=true post-load fallback removes every LSM
// program + LSM-only map while leaving cgroup and shared sections intact.
func TestStripAllLSM(t *testing.T) {
	spec, err := LoadDefend()
	if err != nil {
		t.Fatalf("LoadDefend: %v", err)
	}
	stripAllLSM(spec)

	mustBeGone := []string{
		"lsm_socket_connect",
		"lsm_socket_sendmsg",
		"lsm_socket_sendpage",
		"lsm_io_uring_cmd",
	}
	for _, name := range mustBeGone {
		if _, present := spec.Programs[name]; present {
			t.Errorf("stripAllLSM: program %q still present", name)
		}
	}
	mustBeGoneMaps := []string{
		"lsm_deny_events",
		"lsm_deny_reserve_failures",
		"lsm_defend_cfg",
		"lsm_allowed_ipv4",
		"lsm_ignored_ipv4_lpm",
		"sendpage_observed",
	}
	for _, name := range mustBeGoneMaps {
		if _, present := spec.Maps[name]; present {
			t.Errorf("stripAllLSM: map %q still present", name)
		}
	}
	for _, name := range []string{"defend_connect4", "defend_sendmsg4"} {
		if _, present := spec.Programs[name]; !present {
			t.Errorf("stripAllLSM: cgroup program %q must remain", name)
		}
	}
	for _, name := range []string{"deny_events", "deny_reserve_failures", "defend_cfg", "allowed_ipv4"} {
		if _, present := spec.Maps[name]; !present {
			t.Errorf("stripAllLSM: shared/cgroup map %q must remain", name)
		}
	}
}

// TestLoadResultZeroValueSafe pins the public contract that callers can
// read a zero-value LoadResult without panicking — the caller branch in
// agent_linux.go relies on LSMFellBack defaulting to false and FallbackErr
// being a nil error on the happy path.
func TestLoadResultZeroValueSafe(t *testing.T) {
	var r LoadResult
	if r.LSMFellBack {
		t.Errorf("zero LoadResult.LSMFellBack = true; want false")
	}
	if r.LSMFallbackErr != nil {
		t.Errorf("zero LoadResult.LSMFallbackErr != nil; want nil")
	}
	// errors.Is on a nil error must be safe.
	if errors.Is(r.LSMFallbackErr, errors.New("any")) {
		t.Errorf("errors.Is(nil, _) returned true unexpectedly")
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
