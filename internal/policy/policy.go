// Package policy implements Coldstep v1 IPv4-centric egress allowlists. IPv6 literals and IPv6
// ignored CIDRs are rejected at parse time; BPF enforcement uses IPv4 maps only (see bpf/trace_enforce.bpf.c).
package policy

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"unicode"
)

// MaxIgnoredIPv4Nets is the maximum merged ignored CIDR entries (defaults + user).
// It must match the BPF LPM trie max_entries in trace_enforce.bpf.c.
const MaxIgnoredIPv4Nets = 128

// MaxAllowedEnforceIPv4Keys matches allowed_ipv4 max_entries in bpf/trace_enforce.bpf.c.
const MaxAllowedEnforceIPv4Keys = 4096

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
	ignored      []*net.IPNet        // merged default + user ignored IPv4 CIDRs (BuildPolicy only)
}

// validHostnameSuffix matches purely lowercase DNS label characters for wildcard suffix validation.
var validHostnameSuffix = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$`)

// Parse builds a policy from raw action/env strings (comma or ASCII whitespace).
func Parse(allowedHosts, allowedIPs string) (*Policy, error) {
	p := &Policy{
		exactHosts: make(map[string]struct{}),
		ips:        make(map[string]struct{}),
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
			if !validHostnameSuffix.MatchString(suf) {
				return nil, fmt.Errorf("allowed-hosts: wildcard suffix %q contains invalid hostname characters", suf)
			}
			p.wildSuffixes = append(p.wildSuffixes, suf)
		} else {
			p.exactHosts[h] = struct{}{}
		}
	}
	for _, raw := range splitFields(allowedIPs) {
		raw = strings.TrimSpace(raw)
		if raw == "" {
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
		if ip.To16() != nil {
			return nil, fmt.Errorf("allowed-ips: IPv6 literals are not supported, use IPv4: %q", raw)
		}
		return nil, fmt.Errorf("invalid allowed IP %q", raw)
	}
	p.enabled = len(p.exactHosts) > 0 || len(p.wildSuffixes) > 0 || len(p.ips) > 0
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

// MergeLiteralAllowedIPv4Keys adds IPv4 addresses from COLDSTEP_ALLOWED_IPS-style policy entries
// into keys (used with domain-resolved IPs for enforce-mode BPF allowed_ipv4).
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
			if fqdn == suf || hostMatchesWildcard(fqdn, suf) {
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
