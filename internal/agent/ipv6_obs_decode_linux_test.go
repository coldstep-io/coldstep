//go:build linux

package agent

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"

	"github.com/coldstep-io/coldstep/internal/telemetry"
)

func TestIPv6ObsHookName(t *testing.T) {
	cases := []struct {
		in   uint8
		want string
	}{
		{0, telemetry.EventTypeIPv6TCP},
		{1, telemetry.EventTypeIPv6UDP},
		{2, telemetry.EventTypeIPv6TCP},
		{255, telemetry.EventTypeIPv6TCP},
	}
	for _, c := range cases {
		if got := ipv6ObsHookName(c.in); got != c.want {
			t.Fatalf("ipv6ObsHookName(%d) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestIPv6ObsEventWireDecode pins the wire layout. Offsets are:
//
//	daddr [16] @ 0
//	dport [2]  @ 16  (network byte order)
//	_pad0 [2]  @ 18
//	pid   [4]  @ 20  (little-endian)
//	comm  [16] @ 24
//	hook  [1]  @ 40
//	_pad1 [3]  @ 41
//
// Total: 44 bytes (ipv6ObsEventWireSize). Any change to bpf/trace_ipv6_obs.bpf.c
// that disturbs this layout must update the _Static_assert there AND
// ipv6ObsEventWireSize here.
func TestIPv6ObsEventWireDecode(t *testing.T) {
	if ipv6ObsEventWireSize != 44 {
		t.Fatalf("ipv6ObsEventWireSize = %d, want 44", ipv6ObsEventWireSize)
	}

	raw := make([]byte, ipv6ObsEventWireSize)
	addr := net.ParseIP("2001:db8::1").To16()
	if addr == nil {
		t.Fatalf("ParseIP returned nil")
	}
	copy(raw[0:16], addr)
	binary.BigEndian.PutUint16(raw[16:18], 443)
	binary.LittleEndian.PutUint32(raw[20:24], 1234)
	copy(raw[24:40], []byte("curl\x00"))
	raw[40] = 1 // hook = sendmsg6

	var wire ipv6ObsEventWire
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &wire); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if got := net.IP(wire.Daddr[:]).String(); got != "2001:db8::1" {
		t.Fatalf("daddr = %s, want 2001:db8::1", got)
	}
	if got := binary.BigEndian.Uint16(wire.Dport[:]); got != 443 {
		t.Fatalf("dport = %d, want 443", got)
	}
	if wire.PID != 1234 {
		t.Fatalf("pid = %d, want 1234", wire.PID)
	}
	if got := string(bytes.TrimRight(wire.Comm[:], "\x00")); got != "curl" {
		t.Fatalf("comm = %q, want curl", got)
	}
	if wire.Hook != 1 {
		t.Fatalf("hook = %d, want 1", wire.Hook)
	}
	if got := ipv6ObsHookName(wire.Hook); got != telemetry.EventTypeIPv6UDP {
		t.Fatalf("hookName = %s, want %s", got, telemetry.EventTypeIPv6UDP)
	}
}
