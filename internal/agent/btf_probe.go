//go:build linux

package agent

import (
	"fmt"

	"github.com/cilium/ebpf/btf"
)

// probeBTF checks that kernel BTF is available. Returns nil if available,
// a descriptive error if not. Called early in agent startup so the failure
// message is actionable: kernel BTF is required by every CO-RE-relocated
// BPF program shipped in this agent, and without it the verifier emits
// cryptic relocation failures during prog_load. Surfacing the absence here
// gives operators a single, named cause they can act on (upgrade kernel
// to 5.5+, or rebuild with CONFIG_DEBUG_INFO_BTF=y).
func probeBTF() error {
	if _, err := btf.LoadKernelSpec(); err != nil {
		return fmt.Errorf("kernel BTF unavailable (requires kernel 5.5+ with CONFIG_DEBUG_INFO_BTF=y): %w", err)
	}
	return nil
}
