// Package agent — QUIC/HTTP3 observation heuristic (P2-2).
//
// BPF probes cannot inspect UDP payloads (QUIC is encrypted at the transport
// layer), so coldstep treats UDP egress to port 443 on a non-loopback IPv4
// destination as a *likely* QUIC/HTTP3 flow. The heuristic runs in userspace
// alongside the regular UDP ring reader, so no BPF or clang work is required.
//
// IsQUICCandidate is intentionally cross-platform (no build tag) so the rule
// can be unit-tested on any host. It centralizes the "what counts as QUIC"
// predicate so the agent and the report builder agree.
package agent

import "net"

// IsQUICCandidate returns true when an observed UDP egress is a likely
// QUIC/HTTP3 flow worth surfacing as a visibility-gap event. The rule is:
//
//   - destination port equals 443, AND
//   - destination IP parses as a non-loopback IPv4 address.
//
// Loopback (127.0.0.0/8) is excluded because runner-local UDP/443 traffic is
// almost never QUIC egress to the public internet. IPv6 is not considered;
// coldstep's BPF probes are IPv4-only by design.
func IsQUICCandidate(dstIP string, dstPort uint16) bool {
	if dstPort != 443 {
		return false
	}
	ip := net.ParseIP(dstIP)
	if ip == nil {
		return false
	}
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	return !v4.IsLoopback()
}
