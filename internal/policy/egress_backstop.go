package policy

import "net"

// EgressBackstopBypasses mirrors the loopback / link-local short-circuits in
// bpf/trace_defend_skb.inc (skb_v4_is_loopback / skb_v6_is_loopback /
// skb_v6_is_link_local). It returns true for destinations the cgroup_skb egress
// backstop always allows without emitting an observation. The BPF program is
// authoritative; this is a regression anchor pinning the exact boundary.
func EgressBackstopBypasses(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		return v4[0] == 127 // 127.0.0.0/8
	}
	if ip.IsLoopback() { // ::1
		return true
	}
	// fe80::/10 link-local.
	return len(ip) == net.IPv6len && ip[0] == 0xfe && (ip[1]&0xc0) == 0x80
}
