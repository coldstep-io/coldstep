//go:build linux

package agent

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestEgressBackstopSourceWiring pins sub-project A's BPF wiring: the section is
// included after the cgroup section, the program reuses the address-based
// allowlist helpers, reads packet bytes via bpf_skb_load_bytes, and builds the
// dedup key from a 16-byte array (not an out-of-bounds cast of the 4-byte v4
// daddr — the BG fix from review).
func TestEgressBackstopSourceWiring(t *testing.T) {
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
	cgIdx := strings.Index(ct, `#include "trace_defend_cgroup.inc"`)
	skbIdx := strings.Index(ct, `#include "trace_defend_skb.inc"`)
	if cgIdx < 0 || skbIdx < 0 || !(cgIdx < skbIdx) {
		t.Fatalf("skb section must be included after cgroup: cg=%d skb=%d", cgIdx, skbIdx)
	}

	src, err := os.ReadFile(filepath.Join(root, "bpf", "trace_defend_skb.inc"))
	if err != nil {
		t.Fatalf("read skb inc: %v", err)
	}
	st := string(src)
	if !strings.Contains(st, `SEC("cgroup_skb/egress")`) {
		t.Error("missing cgroup_skb/egress program")
	}
	// The raw 4-byte cmd-union cast bug must not reappear in the dedup call.
	if strings.Contains(st, "skb_backstop_recently_seen((__u8 *)&daddr)") {
		t.Error("v4 dedup must use a 16-byte array, not an OOB cast of &daddr")
	}
	// Reuse the address-based allowlist helpers + bounded packet reads.
	for _, want := range []string{"cg_dst_in_ignored(", "cg_dst_is_allowlisted(", "bpf_skb_load_bytes("} {
		if !strings.Contains(st, want) {
			t.Errorf("missing expected call %q", want)
		}
	}
}
