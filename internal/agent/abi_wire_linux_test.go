//go:build linux

package agent

import (
	"testing"
	"unsafe"
)

// TestEventStructWireSizes asserts that Go-side wire structs match the
// numeric wire-size constants which are themselves locked to the BPF C
// struct sizeof() via _Static_assert in bpf/*.bpf.c. Together these form
// the BPF↔Go ABI guard that closes Theme B (F-U1-04) of the
// 2026-04-18 deep eBPF code review.
func TestEventStructWireSizes(t *testing.T) {
	cases := []struct {
		name     string
		got      uintptr
		expected uintptr
	}{
		{"execEvent", unsafe.Sizeof(execEvent{}), execEventWireSize},
		{"forkEventWire", unsafe.Sizeof(forkEventWire{}), forkEventWireSize},
		{"fsEventWire", unsafe.Sizeof(fsEventWire{}), fsEventWireSize},
	}
	for _, c := range cases {
		if c.got != c.expected {
			t.Errorf("%s: unsafe.Sizeof = %d, want %d (BPF→Go ABI drift)",
				c.name, c.got, c.expected)
		}
	}
}
