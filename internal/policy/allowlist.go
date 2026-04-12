package policy

import (
	"context"
	"errors"
	"net"
	"slices"
	"strings"
)

// LookupIPFunc resolves hostnames to IPs.
type LookupIPFunc func(ctx context.Context, network, host string) ([]net.IP, error)

// IPv4Set stores unique IPv4 addresses in 4-byte form.
type IPv4Set struct {
	items map[[4]byte]struct{}
}

// Add inserts an IPv4 address into the set.
func (s *IPv4Set) Add(ip net.IP) {
	ip4 := ip.To4()
	if ip4 == nil {
		return
	}
	if s.items == nil {
		s.items = make(map[[4]byte]struct{})
	}
	var key [4]byte
	copy(key[:], ip4)
	s.items[key] = struct{}{}
}

// Contains reports whether ip is present in the set.
func (s IPv4Set) Contains(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil || len(s.items) == 0 {
		return false
	}
	var key [4]byte
	copy(key[:], ip4)
	_, ok := s.items[key]
	return ok
}

// Len returns the number of unique IPv4 addresses in the set.
func (s IPv4Set) Len() int {
	return len(s.items)
}

// CompileResult is the deterministic output from allowlist compilation.
type CompileResult struct {
	Domains           []string
	AllowedIPv4       IPv4Set
	UnresolvedDomains []string
}

// CompileDomainAllowlist normalizes and resolves domain allowlist entries.
func CompileDomainAllowlist(ctx context.Context, domains []string, resolver LookupIPFunc, maxAttempts int) CompileResult {
	if resolver == nil {
		resolver = net.DefaultResolver.LookupIP
	}
	if maxAttempts < 1 {
		maxAttempts = 1
	}

	normalized := normalizeAllowlistDomains(domains)
	result := CompileResult{
		Domains:     normalized,
		AllowedIPv4: IPv4Set{items: make(map[[4]byte]struct{})},
	}

	for _, domain := range normalized {
		resolved := false
		for attempt := 0; attempt < maxAttempts; attempt++ {
			if ctx != nil && ctx.Err() != nil {
				break
			}
			ips, err := resolver(ctx, "ip4", domain)
			if err != nil {
				if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					break
				}
				continue
			}
			addedIPv4 := false
			for _, ip := range ips {
				ip4 := ip.To4()
				if ip4 == nil {
					continue
				}
				result.AllowedIPv4.Add(ip4)
				addedIPv4 = true
			}
			if addedIPv4 {
				resolved = true
				break
			}
		}
		if !resolved {
			result.UnresolvedDomains = append(result.UnresolvedDomains, domain)
		}
	}

	slices.Sort(result.UnresolvedDomains)
	return result
}

func normalizeAllowlistDomains(domains []string) []string {
	out := make([]string, 0, len(domains))
	seen := make(map[string]struct{}, len(domains))
	for _, raw := range domains {
		domain := strings.ToLower(strings.TrimSpace(raw))
		if domain == "" {
			continue
		}
		if _, ok := seen[domain]; ok {
			continue
		}
		seen[domain] = struct{}{}
		out = append(out, domain)
	}
	return out
}
