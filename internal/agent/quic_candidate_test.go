package agent

import "testing"

// TestIsQUICCandidate exercises the cross-platform UDP/443 → QUIC predicate
// (P2-2). The agent's UDP ring reader uses this to decide whether to emit a
// synthetic quic_candidate JSONL line alongside the regular udp event; the
// rule must not fire on loopback (runner-local traffic) or non-443 ports.
func TestIsQUICCandidate(t *testing.T) {
	cases := []struct {
		name string
		ip   string
		port uint16
		want bool
	}{
		{"public ipv4 port 443", "1.2.3.4", 443, true},
		{"cloudflare port 443", "104.16.0.1", 443, true},

		{"loopback port 443", "127.0.0.1", 443, false},
		{"loopback 127.0.0.2 port 443", "127.0.0.2", 443, false},
		{"loopback higher in /8 port 443", "127.255.255.254", 443, false},

		{"public ipv4 port 80", "1.2.3.4", 80, false},
		{"public ipv4 port 53", "8.8.8.8", 53, false},
		{"public ipv4 port 0", "1.2.3.4", 0, false},
		{"public ipv4 port 4433", "1.2.3.4", 4433, false},

		{"empty ip port 443", "", 443, false},
		{"garbage ip port 443", "not-an-ip", 443, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsQUICCandidate(tc.ip, tc.port); got != tc.want {
				t.Fatalf("IsQUICCandidate(%q, %d) = %v, want %v", tc.ip, tc.port, got, tc.want)
			}
		})
	}
}
