// Package policy implements Coldstep IPv4-only egress allowlists. IPv6 is not supported; invalid
// literals/CIDRs are rejected at parse time. BPF defend programs use IPv4 maps only.
package policy

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"unicode"
)

// MaxIgnoredIPv4Nets is the maximum merged ignored CIDR entries (defaults + user).
// It must match the BPF LPM trie max_entries in trace_defend.bpf.c.
const MaxIgnoredIPv4Nets = 128

// MaxAllowedDefendIPv4Keys matches allowed_ipv4 max_entries in bpf/trace_defend.bpf.c.
const MaxAllowedDefendIPv4Keys = 4096

// MaxAllowedDefendIPv6Keys matches allowed_ipv6 max_entries in
// bpf/trace_defend_cgroup.inc. Kept symmetric with IPv4 so the abi_test
// pair stays parallel; in practice AAAA resolutions yield fewer entries
// per domain than A records (one AAAA + a few alias addresses), so 4096
// is well above realistic defend-mode demand.
const MaxAllowedDefendIPv6Keys = 4096

// MaxAllowedHostnameBytes is the maximum length of an allowed hostname (exact match or wildcard suffix).
// DNS FQDNs are at most 253 octets (RFC 1035). BPF allowed_domains uses fixed char[256] keys; longer
// names would truncate silently in userspace map updates without this guard.
const MaxAllowedHostnameBytes = 253

// Class describes egress vs allow lists (v1: never fails the job on policy).
type Class string

const (
	ClassMonitor   Class = "monitor" // no allow lists configured
	ClassAllowed   Class = "allowed"
	ClassNotListed Class = "not_listed"
	ClassUnknown   Class = "unknown" // lists on, fqdn empty
	ClassIgnored   Class = "ignored" // destination in ignored CIDR (defaults + user)
)

// Policy is immutable after Parse / BuildPolicy.
type Policy struct {
	enabled      bool
	exactHosts   map[string]struct{}
	wildSuffixes []string            // "*.example.com" -> suffix "example.com"
	ips          map[string]struct{} // IPv4 literals from allowed-ips (4-byte key string)
	nets         []*net.IPNet        // PR-G: literal IPv4 CIDR allowlist entries (e.g. "10.0.0.0/8")
	ignored      []*net.IPNet        // merged default + user ignored IPv4 CIDRs (BuildPolicy only)
	// SP-2: native IPv6 literal allowlist entries. ipv6s holds /128 literals
	// (16-byte key string); ipv6nets holds IPv6 CIDRs (e.g. "2001:db8::/32").
	// Both are programmed into the defend `allowed_ipv6` LPM trie alongside
	// AAAA-resolved domains. IPv4-mapped IPv6 inputs are normalized to IPv4 and
	// kept in ips/nets so the v4 and v6 sets stay disjoint.
	ipv6s    map[string]struct{}
	ipv6nets []*net.IPNet
}

// validHostnameSuffix matches purely lowercase DNS label characters for wildcard suffix validation.
var validHostnameSuffix = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$`)

// Parse builds a policy from raw action/env strings (comma or ASCII whitespace).
func Parse(allowedHosts, allowedIPs string) (*Policy, error) {
	p := &Policy{
		exactHosts: make(map[string]struct{}),
		ips:        make(map[string]struct{}),
		ipv6s:      make(map[string]struct{}),
	}
	for _, h := range splitFields(allowedHosts) {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" {
			continue
		}
		if strings.HasPrefix(h, "*.") {
			suf := strings.TrimPrefix(h, "*.")
			if suf == "" || strings.Contains(suf, "*") {
				continue
			}
			if len(suf) > MaxAllowedHostnameBytes {
				return nil, fmt.Errorf("allowed-hosts: wildcard suffix exceeds maximum length %d bytes", MaxAllowedHostnameBytes)
			}
			if !validHostnameSuffix.MatchString(suf) {
				return nil, fmt.Errorf("allowed-hosts: wildcard suffix %q contains invalid hostname characters", suf)
			}
			p.wildSuffixes = append(p.wildSuffixes, suf)
		} else {
			if len(h) > MaxAllowedHostnameBytes {
				return nil, fmt.Errorf("allowed-hosts: hostname exceeds maximum length %d bytes", MaxAllowedHostnameBytes)
			}
			p.exactHosts[h] = struct{}{}
		}
	}
	for _, raw := range splitFields(allowedIPs) {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		// Accept a bare IPv4 literal (kept as /32 in p.ips for fast Classify
		// exact-match) or an IPv4 CIDR like "10.0.0.0/8" (kept in p.nets and
		// programmed into the BPF allowed_ipv4 LPM trie). SP-2: also accept
		// native IPv6 literals (-> p.ipv6s) and IPv6 CIDRs (-> p.ipv6nets) for
		// the allowed_ipv6 trie. IPv4-mapped IPv6 is normalized to IPv4.
		if strings.Contains(raw, "/") {
			ip, ipNet, err := net.ParseCIDR(raw)
			if err != nil {
				return nil, fmt.Errorf("allowed-ips: invalid CIDR %q: %w", raw, err)
			}
			if ip.To4() != nil {
				p.nets = append(p.nets, ipNet)
			} else {
				p.ipv6nets = append(p.ipv6nets, ipNet)
			}
			continue
		}
		ip := net.ParseIP(raw)
		if ip == nil {
			return nil, fmt.Errorf("invalid allowed IP %q", raw)
		}
		if ip4 := ip.To4(); ip4 != nil {
			p.ips[string(ip4)] = struct{}{}
			continue
		}
		if ip16 := ip.To16(); ip16 != nil {
			p.ipv6s[string(ip16)] = struct{}{}
			continue
		}
		return nil, fmt.Errorf("invalid allowed IP %q", raw)
	}
	if len(p.ipv6s) > MaxAllowedDefendIPv6Keys || len(p.ipv6nets) > MaxAllowedDefendIPv6Keys {
		return nil, fmt.Errorf("allowed-ips: IPv6 entry count exceeds maximum %d", MaxAllowedDefendIPv6Keys)
	}
	p.enabled = len(p.exactHosts) > 0 || len(p.wildSuffixes) > 0 || len(p.ips) > 0 || len(p.nets) > 0 || len(p.ipv6s) > 0 || len(p.ipv6nets) > 0
	return p, nil
}

// BuildPolicy parses allowlists like Parse, then attaches merged default + user ignored IPv4 CIDRs.
func BuildPolicy(allowedHosts, allowedIPs, ignoredIPNets string) (*Policy, error) {
	return BuildPolicyEx(allowedHosts, allowedIPs, ignoredIPNets, true)
}

// BuildPolicyEx is like BuildPolicy; when mergeDefaultRFC1918Ignored is false, only ignoredIPNets
// is used (no implicit 10.0.0.0/8 or 172.16.0.0/12).
func BuildPolicyEx(allowedHosts, allowedIPs, ignoredIPNets string, mergeDefaultRFC1918Ignored bool) (*Policy, error) {
	p, err := Parse(allowedHosts, allowedIPs)
	if err != nil {
		return nil, err
	}
	user, err := ParseIgnoredIPNets(ignoredIPNets)
	if err != nil {
		return nil, err
	}
	var merged []*net.IPNet
	if mergeDefaultRFC1918Ignored {
		merged, err = MergeDefaultIgnoredNets(user)
		if err != nil {
			return nil, err
		}
	} else {
		merged = mergeDedupedNets(nil, user)
	}
	if len(merged) > MaxIgnoredIPv4Nets {
		return nil, fmt.Errorf("ignored IPv4 CIDR count %d exceeds maximum %d", len(merged), MaxIgnoredIPv4Nets)
	}
	p.ignored = merged
	return p, nil
}

// IgnoredIPv4Nets returns the ignored CIDR list (immutable slice; do not mutate).
func (p *Policy) IgnoredIPv4Nets() []*net.IPNet {
	if p == nil {
		return nil
	}
	return p.ignored
}

// AllowedDomains returns the exact allowed hostnames from the policy.
// Wildcard entries (e.g. *.example.com) are NOT returned; the BPF allowed_domains
// map uses exact-string lookup and cannot match wildcards. Use HasWildSuffixes to
// detect wildcard entries and warn when defend mode is active.
func (p *Policy) AllowedDomains() []string {
	if p == nil {
		return nil
	}
	out := make([]string, 0, len(p.exactHosts))
	for h := range p.exactHosts {
		out = append(out, h)
	}
	return out
}

// HasWildSuffixes reports whether the policy contains any wildcard allowed-hosts entries
// (e.g. *.example.com). These are matched by Classify but are NOT loaded into the BPF
// allowed_domains map, so they have no effect in defend mode.
func (p *Policy) HasWildSuffixes() bool {
	return p != nil && len(p.wildSuffixes) > 0
}

// MergeLiteralAllowedIPv4Keys adds IPv4 addresses from COLDSTEP_ALLOWED_IPS-style policy entries
// into keys (used with domain-resolved IPs for defend-mode BPF allowed_ipv4).
func (p *Policy) MergeLiteralAllowedIPv4Keys(keys map[[4]byte]struct{}) {
	if p == nil || keys == nil || len(p.ips) == 0 {
		return
	}
	for s := range p.ips {
		if len(s) != net.IPv4len {
			continue
		}
		var k [4]byte
		copy(k[:], s)
		keys[k] = struct{}{}
	}
}

// MergeLiteralAllowedIPv4Into adds literal allowed IPv4 addresses into s (union with domain resolutions).
func (p *Policy) MergeLiteralAllowedIPv4Into(s *IPv4Set) {
	if p == nil || s == nil || len(p.ips) == 0 {
		return
	}
	for sKey := range p.ips {
		if len(sKey) != net.IPv4len {
			continue
		}
		s.Add(net.IP([]byte(sKey)))
	}
}

// AllowedIPv4Nets returns literal CIDR allowlist entries (PR-G) parsed from
// allowed-ips. Bare-IPv4 literals from p.ips are NOT included here — the
// userspace loadDefendMaps caller programs them as /32 LPM keys via the
// existing IPv4Set / map[[4]byte] flow. Returns nil when no CIDRs were given.
func (p *Policy) AllowedIPv4Nets() []*net.IPNet {
	if p == nil {
		return nil
	}
	return p.nets
}

// MergeLiteralAllowedIPv6Into adds literal allowed IPv6 addresses (SP-2) into s,
// unioned with AAAA domain resolutions, for the defend allowed_ipv6 LPM trie.
func (p *Policy) MergeLiteralAllowedIPv6Into(s *IPv6Set) {
	if p == nil || s == nil || len(p.ipv6s) == 0 {
		return
	}
	for sKey := range p.ipv6s {
		if len(sKey) != net.IPv6len {
			continue
		}
		s.Add(net.IP([]byte(sKey)))
	}
}

// AllowedIPv6Nets returns literal IPv6 CIDR allowlist entries (SP-2) parsed from
// allowed-ips. Bare-IPv6 literals from p.ipv6s are NOT included here — they are
// programmed as /128 LPM keys via the IPv6Set flow (MergeLiteralAllowedIPv6Into).
// Returns nil when no IPv6 CIDRs were given.
func (p *Policy) AllowedIPv6Nets() []*net.IPNet {
	if p == nil {
		return nil
	}
	return p.ipv6nets
}

func splitFields(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || unicode.IsSpace(r)
	})
}

func hostMatchesWildcard(fqdn, suffix string) bool {
	if !strings.HasSuffix(fqdn, "."+suffix) {
		return false
	}
	prefix := strings.TrimSuffix(fqdn, "."+suffix)
	return prefix != "" && !strings.Contains(prefix, ".")
}

// Classify evaluates observed egress. ip must be IPv4 for matching.
func (p *Policy) Classify(fqdn string, ip net.IP) Class {
	if p == nil {
		return ClassMonitor
	}
	ip4 := ip.To4()
	if ip4 != nil && p.enabled {
		if _, ok := p.ips[string(ip4)]; ok {
			return ClassAllowed
		}
		// PR-G: also honour literal CIDR allowlist entries so the Go-side
		// classifier matches BPF defend programs (which now do LPM lookup).
		if len(p.nets) > 0 && NetsContains(p.nets, ip4) {
			return ClassAllowed
		}
	}
	if ip4 != nil && len(p.ignored) > 0 && NetsContains(p.ignored, ip4) {
		return ClassIgnored
	}
	if !p.enabled {
		return ClassMonitor
	}
	fqdn = strings.ToLower(strings.TrimSpace(fqdn))
	if fqdn != "" {
		if _, ok := p.exactHosts[fqdn]; ok {
			return ClassAllowed
		}
		for _, suf := range p.wildSuffixes {
			if hostMatchesWildcard(fqdn, suf) {
				return ClassAllowed
			}
		}
		return ClassNotListed
	}
	return ClassUnknown
}

// Display renders a short Markdown table cell.
func (c Class) Display() string {
	switch c {
	case ClassMonitor:
		return "monitor"
	case ClassAllowed:
		return "allowed"
	case ClassNotListed:
		return "not listed"
	case ClassUnknown:
		return "unknown"
	case ClassIgnored:
		return "ignored"
	default:
		return string(c)
	}
}
