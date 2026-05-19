//go:build linux

package agent

import "testing"

// TestProbeBTF_DoesNotPanic exercises probeBTF on the test host. On a hosted
// ubuntu-latest runner with CONFIG_DEBUG_INFO_BTF=y the probe is expected to
// succeed; on kernels or sandboxes without /sys/kernel/btf/vmlinux it may
// return an error. Either outcome is informational here — the test exists to
// guard against panics, signature drift, and missing-import regressions in
// the probe itself, not to assert the host kernel's BTF state.
func TestProbeBTF_DoesNotPanic(t *testing.T) {
	if err := probeBTF(); err != nil {
		t.Logf("probeBTF returned error (may be expected on this kernel): %v", err)
	}
}
