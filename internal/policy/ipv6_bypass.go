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
// (::ffff:0:0/96) are NOT bypass and NOT ordinary IPv6 — a dual-stack socket
// can connect to ::ffff:a.b.c.d and reach the IPv6 cgroup hook, so the BPF
// program routes the embedded IPv4 to the IPv4 allowlist instead (see
// cg_ipv6_is_v4mapped + IPv4MappedEmbeddedIPv4). This function returns false
// for them; IPv4MappedEmbeddedIPv4 is the classifier that matters there.
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

// IPv4MappedEmbeddedIPv4 reports whether ip is an IPv4-mapped IPv6 address
// (::ffff:0:0/96) and, if so, returns the embedded 4-byte IPv4. This is the
// userspace mirror of cg_ipv6_is_v4mapped in bpf/trace_defend_cgroup.inc: a
// dual-stack socket connecting to ::ffff:a.b.c.d reaches the cgroup/connect6 +
// sendmsg6 hooks, which must gate the embedded IPv4 against the IPv4 allowlist
// (allowed_ipv4 / ignored trie) rather than the AAAA-only allowed_ipv6 trie —
// otherwise a v4-mapped connection to an allowlisted IPv4 is falsely denied.
//
// The prefix test (bytes 0-9 zero, bytes 10-11 == 0xff) mirrors the BPF check
// `user_ip6[0]==0 && user_ip6[1]==0 && user_ip6[2]==htonl(0x0000ffff)`. Keep
// the two in lockstep.
func IPv4MappedEmbeddedIPv4(ip net.IP) (net.IP, bool) {
	ip16 := ip.To16()
	if ip16 == nil {
		return nil, false
	}
	for i := 0; i < 10; i++ {
		if ip16[i] != 0 {
			return nil, false
		}
	}
	if ip16[10] != 0xff || ip16[11] != 0xff {
		return nil, false
	}
	out := make(net.IP, net.IPv4len)
	copy(out, ip16[12:16])
	return out, true
}
