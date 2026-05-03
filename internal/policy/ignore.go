package policy

import (
	"fmt"
	"net"
	"strings"
	"unicode"
)

// ParseIgnoredIPNets parses comma- or ASCII-whitespace-separated IPv4 CIDRs.
// IPv6 is not supported.
func ParseIgnoredIPNets(raw string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, tok := range splitIgnoredRawFields(raw) {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		_, ipnet, err := net.ParseCIDR(tok)
		if err != nil {
			return nil, fmt.Errorf("invalid ignored CIDR %q: %w", tok, err)
		}
		if ipnet.IP.To4() == nil {
			return nil, fmt.Errorf("ignored CIDR must be IPv4, not IPv6: %q", tok)
		}
		out = append(out, &net.IPNet{
			IP:   ipnet.IP.To4(),
			Mask: ipnet.Mask,
		})
	}
	return out, nil
}

// splitIgnoredRawFields matches policy.splitFields (comma or ASCII whitespace).
func splitIgnoredRawFields(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || unicode.IsSpace(r)
	})
}

// DefaultIgnoredIPv4Nets returns the implicit RFC1918 private-network ranges
// (10.0.0.0/8 and 172.16.0.0/12), matching common CI internal-network baselines.
//
// Why 192.168.0.0/16 is intentionally OMITTED from the defaults:
// GitHub-hosted Azure runners route their VM-internal management traffic
// through 10.0.0.0/8 and 172.16.0.0/12 only; user-controlled labs / on-prem
// runners that use 192.168/16 frequently want that traffic captured (NAS,
// LDAP, internal HTTP services on a home-lab subnet) so silently masking
// it would degrade observability for the most common self-hosted scenarios.
// Users on a 192.168/16 LAN that *do* want it masked can pass
// `--ignored-ip-nets 192.168.0.0/16` explicitly.
// See knowledge/reports/2026-04-18-deep-ebpf-code-review-synthesis.md F-U3-01.
func DefaultIgnoredIPv4Nets() ([]*net.IPNet, error) {
	return ParseIgnoredIPNets("10.0.0.0/8 172.16.0.0/12")
}

// mergeDedupedNets appends b after a, dropping exact duplicate CIDR strings.
func mergeDedupedNets(a, b []*net.IPNet) []*net.IPNet {
	seen := make(map[string]struct{}, len(a)+len(b))
	out := make([]*net.IPNet, 0, len(a)+len(b))
	for _, list := range [][]*net.IPNet{a, b} {
		for _, n := range list {
			if n == nil {
				continue
			}
			s := n.String()
			if _, ok := seen[s]; ok {
				continue
			}
			seen[s] = struct{}{}
			ip := n.IP.To4()
			if ip == nil {
				continue
			}
			mlen := len(n.Mask)
			mask := make(net.IPMask, mlen)
			copy(mask, n.Mask)
			ipCopy := make(net.IP, len(ip))
			copy(ipCopy, ip)
			out = append(out, &net.IPNet{IP: ipCopy, Mask: mask})
		}
	}
	return out
}

// MergeDefaultIgnoredNets merges DefaultIgnoredIPv4Nets with user-provided nets.
func MergeDefaultIgnoredNets(user []*net.IPNet) ([]*net.IPNet, error) {
	def, err := DefaultIgnoredIPv4Nets()
	if err != nil {
		return nil, err
	}
	return mergeDedupedNets(def, user), nil
}

// NetsContains reports whether ip4 (IPv4) falls in any of nets.
func NetsContains(nets []*net.IPNet, ip4 net.IP) bool {
	if len(nets) == 0 || ip4 == nil {
		return false
	}
	ip4 = ip4.To4()
	if ip4 == nil {
		return false
	}
	for _, n := range nets {
		if n != nil && n.Contains(ip4) {
			return true
		}
	}
	return false
}
