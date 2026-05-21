//go:build linux

package agent

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestDefendIOUringIncludedInCombinedSource asserts H15's
// trace_lsm_defend_iouring.inc is wired into bpf/trace_defend_all.bpf.c.
// Cheap and Linux-only because the source tree layout is reachable from
// runtime.Caller — no clang or BPF load needed.
func TestDefendIOUringIncludedInCombinedSource(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}

	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))
	combinedPath := filepath.Join(repoRoot, "bpf", "trace_defend_all.bpf.c")

	src, err := os.ReadFile(combinedPath)
	if err != nil {
		t.Fatalf("read %s: %v", combinedPath, err)
	}
	text := string(src)
	if !strings.Contains(text, `#include "trace_lsm_defend_iouring.inc"`) {
		t.Fatal(`trace_defend_all.bpf.c must #include "trace_lsm_defend_iouring.inc" after the LSM section`)
	}

	cgroupIdx := strings.Index(text, `#include "trace_defend_cgroup.inc"`)
	lsmIdx := strings.Index(text, `#include "trace_lsm_defend_lsm.inc"`)
	ioIdx := strings.Index(text, `#include "trace_lsm_defend_iouring.inc"`)
	if cgroupIdx < 0 || lsmIdx < 0 || ioIdx < 0 {
		t.Fatalf("missing include: cgroup=%d lsm=%d iouring=%d", cgroupIdx, lsmIdx, ioIdx)
	}
	if !(cgroupIdx < lsmIdx && lsmIdx < ioIdx) {
		t.Fatalf("includes out of order: cgroup must come before lsm, lsm before iouring; got cgroup=%d lsm=%d iouring=%d", cgroupIdx, lsmIdx, ioIdx)
	}
}

// TestDefendIOUringHookShape checks the new BPF C source uses the lsm_*
// policy helpers (so the existing LSM allowlist/dns_cache machinery is
// shared) and bounds every kernel read so deny-on-error preserves the
// fail-open guarantee for non-socket files.
func TestDefendIOUringHookShape(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))
	srcPath := filepath.Join(repoRoot, "bpf", "trace_lsm_defend_iouring.inc")

	src, err := os.ReadFile(srcPath)
	if err != nil {
		t.Fatalf("read %s: %v", srcPath, err)
	}
	text := string(src)

	required := []string{
		`SEC("lsm/io_uring_cmd")`,
		"BPF_PROG(lsm_io_uring_cmd, struct io_uring_cmd *ioucmd)",
		"lsm_defense_enabled()",
		"lsm_dst_in_ignored(daddr)",
		"lsm_dst_is_allowlisted(daddr)",
		"lsm_emit_deny_event_ipv4(proto, addr_bytes, dport,",
		"return -EPERM;",
	}
	for _, want := range required {
		if !strings.Contains(text, want) {
			t.Fatalf("trace_lsm_defend_iouring.inc must contain %q", want)
		}
	}

	// Every bpf_probe_read_kernel result is checked; the file must not call
	// the helper without inspecting its return value (audit 5f).
	if strings.Contains(text, "\n\tbpf_probe_read_kernel(") {
		t.Fatal("trace_lsm_defend_iouring.inc has an unchecked bpf_probe_read_kernel call; wrap each in an `if`")
	}
}
