//go:build linux

package agent

import (
	"testing"

	"github.com/coldstep-io/coldstep/internal/telemetry"
)

// TestBuildCoverageReport covers the H5 v0.2.9 telemetry-stub composition:
// - IPv4 TCP / UDP sendmsg always true (always-wired cgroup hooks)
// - IPv6 / QUICHTTP3 always false (probes not yet implemented)
// - TLSSNI flips on gate + non-degraded probe; "none" otherwise
// - IoUring tracks ioUringRd.R != nil at MetaEvent build time
func TestBuildCoverageReport(t *testing.T) {
	t.Parallel()

	const tlsSniffHook = "raw_tp/sys_enter (connect, sendto, http sniff, tls)"

	cases := []struct {
		name        string
		bpf         []telemetry.BPFStatus
		tlsGate     bool
		ioUring     bool
		wantTLSSNI  string
		wantIoUring bool
	}{
		{
			name:        "default detect — gate off",
			bpf:         []telemetry.BPFStatus{{Name: tlsSniffHook, OK: true}},
			tlsGate:     false,
			ioUring:     false,
			wantTLSSNI:  "none",
			wantIoUring: false,
		},
		{
			name:        "gate on + probe ok → full",
			bpf:         []telemetry.BPFStatus{{Name: tlsSniffHook, OK: true}},
			tlsGate:     true,
			ioUring:     false,
			wantTLSSNI:  "full",
			wantIoUring: false,
		},
		{
			name:        "gate on + probe degraded → none",
			bpf:         []telemetry.BPFStatus{{Name: tlsSniffHook, OK: false, Detail: "attach failed"}},
			tlsGate:     true,
			ioUring:     false,
			wantTLSSNI:  "none",
			wantIoUring: false,
		},
		{
			name:        "gate on + probe missing from bpf list → none",
			bpf:         []telemetry.BPFStatus{},
			tlsGate:     true,
			ioUring:     false,
			wantTLSSNI:  "none",
			wantIoUring: false,
		},
		{
			name:        "io_uring attached → true",
			bpf:         []telemetry.BPFStatus{{Name: tlsSniffHook, OK: true}},
			tlsGate:     true,
			ioUring:     true,
			wantTLSSNI:  "full",
			wantIoUring: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := buildCoverageReport(tc.bpf, tc.tlsGate, tc.ioUring)
			if got == nil {
				t.Fatal("expected non-nil CoverageReport")
			}
			if !got.IPv4TCP {
				t.Errorf("IPv4TCP = false, want true (always-wired cgroup hook)")
			}
			if !got.IPv4UDPSendmsg {
				t.Errorf("IPv4UDPSendmsg = false, want true (always-wired cgroup hook)")
			}
			if got.IPv6 {
				t.Errorf("IPv6 = true, want false until probe ships")
			}
			if got.QUICHTTP3 {
				t.Errorf("QUICHTTP3 = true, want false until probe ships")
			}
			if got.TLSSNI != tc.wantTLSSNI {
				t.Errorf("TLSSNI = %q, want %q", got.TLSSNI, tc.wantTLSSNI)
			}
			if got.IoUring != tc.wantIoUring {
				t.Errorf("IoUring = %v, want %v", got.IoUring, tc.wantIoUring)
			}
		})
	}
}
