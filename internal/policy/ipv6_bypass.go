package policy

import "net"

// IPv6BypassesDefend reports whether an IPv6 destination address is always
// allowed past defend-mode enforcement, irrespective of the AAAA-resolved
// `allowed_ipv6` LPM trie contents.
//
// This is the userspace mirror of the BPF helpers `cg_ipv6_is_loopback` and
// `cg_ipv6_is_link_local` in bpf/trace_defend_cgroup.inc. The classification
// matters in two places:
//   - The BPF cgroup/connect6 + cgroup/sendmsg6 programs short-circuit and
//     return 1 (allow) before consulting the LPM trie when this function
//     would return true. Test runners' localhost IPv6 traffic and IPv6
//     neighbour-discovery / mDNS / SLAAC stay unblocked.
//   - Userspace allowlist compilation does NOT need to insert ::1/128 or
//     fe80::/10 into the `allowed_ipv6` trie — the BPF program bypasses
//     them upstream of the lookup.
//
// Keep this function and the C helpers in lockstep. Drift means either
// localhost IPv6 starts getting denied (false-negative bypass) or arbitrary
// fe80:: traffic gets implicitly allowed at runtime when it shouldn't have
// been (false-positive bypass).
//
// Classes that bypass enforcement:
//   - ::1 (loopback, RFC 4291 §2.5.3)
//   - fe80::/10 (link-local unicast, RFC 4291 §2.5.6) — covers fe80:: through
//     febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff
//
// Any other class (including ::, unique-local fc00::/7, multicast ff00::/8,
// and globally routable 2000::/3) is NOT bypassed: those addresses go
// through the LPM trie and are denied if absent. IPv4-mapped IPv6 inputs
// (::ffff:0:0/96) are not considered bypass either — they should never
// reach the IPv6 cgroup hook in practice (the kernel routes them through
// the IPv4 path) but defensive coding treats them as ordinary IPv6.
func IPv6BypassesDefend(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.To4() != nil {
		return false
	}
	ip16 := ip.To16()
	if ip16 == nil {
		return false
	}
	if ip16.IsLoopback() {
		return true
	}
	// fe80::/10: first 10 bits are 1111111010, equivalently the first byte is
	// 0xfe and the high 2 bits of the second byte are 0b10 (i.e. byte[1] & 0xc0
	// == 0x80). Matches the BPF check `(user_ip6[0] & htonl(0xffc00000))
	// == htonl(0xfe800000)`.
	return ip16[0] == 0xfe && (ip16[1]&0xc0) == 0x80
}
