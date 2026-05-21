//go:build linux

package agent

import (
	"testing"

	"github.com/coldstep-io/coldstep/internal/telemetry"
)

// TestBuildCoverageReport covers the H5 v0.2.9 telemetry-stub composition:
// - IPv4 TCP / UDP sendmsg always true (always-wired cgroup hooks)
// - QUICHTTP3 always false (probe not yet implemented)
// - IPv6 (H14): "enforce" when defend mode + cgroup6 hooks loaded, "off" otherwise
// - TLSSNI flips on gate + non-degraded probe; "none" otherwise
// - IoUring tracks ioUringRd.R != nil at MetaEvent build time
func TestBuildCoverageReport(t *testing.T) {
	t.Parallel()

	const tlsSniffHook = "raw_tp/sys_enter (connect, sendto, http sniff, tls)"

	cases := []struct {
		name             string
		bpf              []telemetry.BPFStatus
		tlsGate          bool
		ioUring          bool
		ipv6Enforced     bool
		quicObserved     uint64
		wantTLSSNI       string
		wantIoUring      bool
		wantIPv6         string
		wantQuicObserved uint64
	}{
		{
			name:        "default detect — gate off",
			bpf:         []telemetry.BPFStatus{{Name: tlsSniffHook, OK: true}},
			tlsGate:     false,
			ioUring:     false,
			wantTLSSNI:  "none",
			wantIoUring: false,
			wantIPv6:    telemetry.CoverageIPv6Off,
		},
		{
			name:        "gate on + probe ok → full",
			bpf:         []telemetry.BPFStatus{{Name: tlsSniffHook, OK: true}},
			tlsGate:     true,
			ioUring:     false,
			wantTLSSNI:  "full",
			wantIoUring: false,
			wantIPv6:    telemetry.CoverageIPv6Off,
		},
		{
			name:        "gate on + probe degraded → none",
			bpf:         []telemetry.BPFStatus{{Name: tlsSniffHook, OK: false, Detail: "attach failed"}},
			tlsGate:     true,
			ioUring:     false,
			wantTLSSNI:  "none",
			wantIoUring: false,
			wantIPv6:    telemetry.CoverageIPv6Off,
		},
		{
			name:        "gate on + probe missing from bpf list → none",
			bpf:         []telemetry.BPFStatus{},
			tlsGate:     true,
			ioUring:     false,
			wantTLSSNI:  "none",
			wantIoUring: false,
			wantIPv6:    telemetry.CoverageIPv6Off,
		},
		{
			name:        "io_uring attached → true",
			bpf:         []telemetry.BPFStatus{{Name: tlsSniffHook, OK: true}},
			tlsGate:     true,
			ioUring:     true,
			wantTLSSNI:  "full",
			wantIoUring: true,
			wantIPv6:    telemetry.CoverageIPv6Off,
		},
		{
			name:         "defend mode IPv6 enforced → enforce",
			bpf:          []telemetry.BPFStatus{{Name: tlsSniffHook, OK: true}},
			tlsGate:      true,
			ioUring:      false,
			ipv6Enforced: true,
			wantTLSSNI:   "full",
			wantIoUring:  false,
			wantIPv6:     telemetry.CoverageIPv6Enforce,
		},
		{
			name:             "quic observed propagates to report (H19)",
			bpf:              []telemetry.BPFStatus{{Name: tlsSniffHook, OK: true}},
			tlsGate:          false,
			ioUring:          false,
			quicObserved:     7,
			wantTLSSNI:       "none",
			wantIoUring:      false,
			wantIPv6:         telemetry.CoverageIPv6Off,
			wantQuicObserved: 7,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := buildCoverageReport(tc.bpf, tc.tlsGate, tc.ioUring, tc.ipv6Enforced, tc.quicObserved)
			if got == nil {
				t.Fatal("expected non-nil CoverageReport")
			}
			if !got.IPv4TCP {
				t.Errorf("IPv4TCP = false, want true (always-wired cgroup hook)")
			}
			if !got.IPv4UDPSendmsg {
				t.Errorf("IPv4UDPSendmsg = false, want true (always-wired cgroup hook)")
			}
			if got.IPv6 != tc.wantIPv6 {
				t.Errorf("IPv6 = %q, want %q", got.IPv6, tc.wantIPv6)
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
			if got.QuicObserved != tc.wantQuicObserved {
				t.Errorf("QuicObserved = %d, want %d", got.QuicObserved, tc.wantQuicObserved)
			}
		})
	}
}
