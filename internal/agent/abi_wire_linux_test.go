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

// TestNetworkAndAuditWireSizes guards wire-size constants for network and
// audit records that are decoded from raw ringbuf bytes (no Go mirror struct).
func TestNetworkAndAuditWireSizes(t *testing.T) {
	cases := []struct {
		name     string
		got      uintptr
		expected uintptr
	}{
		{"connect_event", uintptr(connectEventWireSize), uintptr(4 + 4 + 16 + 4 + 2 + 2)},
		{"udp_send_event", uintptr(udpSendEventWireSize), uintptr(4 + 4 + 16 + 4 + 2 + 2 + 4)},
		{"http_sniff_event", uintptr(httpSniffEventWireSize), uintptr(httpSniffEventHeaderSize + httpPayloadMax + 2)},
		{"tls_sniff_event", uintptr(tlsSniffEventWireSize), uintptr(tlsSniffEventHeaderSize + tlsPayloadMax + 2)},
		{"http_sniff_event_header", uintptr(httpSniffEventHeaderSize), uintptr(4 + 4 + 16 + 4 + 2 + 2 + 2)},
		{"tls_sniff_event_header", uintptr(tlsSniffEventHeaderSize), uintptr(4 + 4 + 16 + 4 + 2 + 2 + 2)},
		{"deny_event", uintptr(denyEventWireSize), uintptr(4 + 4 + 16 + 1 + 1 + 1 + 1 + 16 + 2)},
		{"bpf_audit_event", uintptr(bpfAuditEventWireSize), uintptr(4 + 4 + 4 + 16)},
		{"dns_sniff_event_legacy", uintptr(dnsSniffEventWireSizeLegacy), uintptr(4 + dnsSniffMaxPayload)},
		{"dns_sniff_event", uintptr(dnsSniffEventWireSize), uintptr(4 + 1 + 3 + dnsSniffMaxPayload)},
	}
	for _, c := range cases {
		if c.got != c.expected {
			t.Errorf("%s: wire size = %d, want %d (BPF→Go ABI drift)",
				c.name, c.got, c.expected)
		}
	}
}
