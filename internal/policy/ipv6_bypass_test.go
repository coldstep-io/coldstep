package policy

import (
	"net"
	"testing"
)

// TestIPv6BypassesDefend pins the userspace mirror of the BPF
// cg_ipv6_is_loopback / cg_ipv6_is_link_local helpers (H14 v0.4.0).
// Drift here is a defend-bypass risk — either localhost stops working or
// fe80:: traffic starts slipping past the LPM trie unenforced.
func TestIPv6BypassesDefend(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		ip   string
		want bool
	}{
		// Loopback (RFC 4291 §2.5.3) — bypass.
		{"loopback ::1", "::1", true},

		// Link-local fe80::/10 — every variant must bypass.
		{"link-local fe80::1", "fe80::1", true},
		{"link-local fe80:: lower bound", "fe80::", true},
		{"link-local febf:: upper bound (still /10)", "febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true},
		{"link-local fe80::1%eth0 (zone stripped by ParseIP)", "fe80::1", true},

		// fec0::/10 (deprecated site-local) is OUTSIDE fe80::/10 — must NOT bypass.
		{"site-local fec0::1 (out of fe80::/10)", "fec0::1", false},
		// fe00::/10 starts at fe00 which is below fe80 — must NOT bypass.
		{"fe00::1 below fe80::/10", "fe00::1", false},

		// Unspecified, unique-local, multicast, global — all enforced.
		{"unspecified ::", "::", false},
		{"unique-local fc00::1", "fc00::1", false},
		{"unique-local fd00::1", "fd00::1", false},
		{"multicast ff02::1", "ff02::1", false},
		{"global 2001:db8::1", "2001:db8::1", false},
		{"global 2606:4700::1 (Cloudflare)", "2606:4700::1", false},

		// IPv4 inputs are rejected — the IPv6 hook never sees them.
		{"IPv4 1.2.3.4 not classified as IPv6 bypass", "1.2.3.4", false},
		{"IPv4 127.0.0.1 not classified as IPv6 bypass", "127.0.0.1", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ip := net.ParseIP(tc.ip)
			if ip == nil {
				t.Fatalf("ParseIP(%q) returned nil", tc.ip)
			}
			got := IPv6BypassesDefend(ip)
			if got != tc.want {
				t.Errorf("IPv6BypassesDefend(%q) = %v, want %v", tc.ip, got, tc.want)
			}
		})
	}
}

// TestIPv6BypassesDefend_NilSafe pins the nil handling — net.ParseIP returns
// nil for malformed input, and a caller threading that into IPv6BypassesDefend
// should get a definite "no bypass" answer.
func TestIPv6BypassesDefend_NilSafe(t *testing.T) {
	t.Parallel()
	if IPv6BypassesDefend(nil) {
		t.Fatal("IPv6BypassesDefend(nil) returned true, want false")
	}
}
