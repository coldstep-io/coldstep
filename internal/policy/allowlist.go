package policy

import (
	"context"
	"errors"
	"net"
	"slices"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"
)

// coldstepDomainLookupAttemptTimeout caps a single Resolver.LookupIP call so goroutines cannot
// block past the parent compile context (hosted runners / flaky resolvers).
const coldstepDomainLookupAttemptTimeout = 25 * time.Second

// coldstepDomainLookupConcurrencyLimit bounds the number of in-flight DNS
// resolutions across the whole allowlist compile, preventing fork-bomb of
// goroutines for large allowlists (Theme F of the 2026-04-18 review).
//
// Pre-PR-F the code spawned `len(domains)` goroutines unbounded; an enforce
// allowlist with 500+ entries (e.g. typical SaaS dependency surface) would
// trigger 500 simultaneous net.Resolver.LookupIP calls, each with its own
// /etc/resolv.conf reads + UDP socket + retry timer. That overwhelms the
// stub-resolver on GitHub-hosted runners and can hit the systemd-resolved
// per-process socket budget. 32 keeps the resolver pipeline saturated
// without thrashing it; chosen empirically to be a multiple of typical
// hosted-runner CPU count (2-4) with headroom for I/O parallelism.
const coldstepDomainLookupConcurrencyLimit = 32

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

// ForEach calls fn for every key in the set.
func (s IPv4Set) ForEach(fn func(k [4]byte)) {
	for k := range s.items {
		fn(k)
	}
}

// CompileResult is the deterministic output from allowlist compilation.
type CompileResult struct {
	Domains           []string
	AllowedIPv4       IPv4Set
	UnresolvedDomains []string
}

// CompileDomainAllowlist normalizes and resolves domain allowlist entries.
// Resolution is performed concurrently (one goroutine per domain) to avoid
// O(n) sequential latency when enforce mode has a large allowlist.
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

	type domainResult struct {
		domain   string
		ips      []net.IP
		resolved bool
	}

	results := make([]domainResult, len(normalized))

	// errgroup.SetLimit bounds in-flight goroutines to N; Go() blocks on the
	// internal semaphore once N goroutines are running. Workers never return
	// an error (resolution failures land in domainResult.resolved=false), so
	// the eg.Wait() error is unconditionally nil — but using errgroup over a
	// hand-rolled sync.WaitGroup + chan-semaphore keeps the bounded-concurrency
	// pattern self-documenting and cancels via parent-ctx if Coldstep ever
	// switches to a context-cancellation model for compile timeouts.
	if ctx == nil {
		ctx = context.Background()
	}
	eg, gctx := errgroup.WithContext(ctx)
	eg.SetLimit(coldstepDomainLookupConcurrencyLimit)
	for i, domain := range normalized {
		idx, d := i, domain
		eg.Go(func() error {
			res := domainResult{domain: d}
			for attempt := 0; attempt < maxAttempts; attempt++ {
				if gctx.Err() != nil {
					break
				}
				lookupCtx, cancel := context.WithTimeout(gctx, coldstepDomainLookupAttemptTimeout)
				ips4, err4 := resolver(lookupCtx, "ip4", d)
				cancel()
				if err4 != nil && (errors.Is(err4, context.Canceled) || errors.Is(err4, context.DeadlineExceeded)) {
					break
				}
				if err4 == nil {
					for _, ip := range ips4 {
						if ip.To4() != nil {
							res.ips = append(res.ips, ip)
							res.resolved = true
						}
					}
				}
				if res.resolved {
					break
				}
			}
			results[idx] = res
			return nil
		})
	}
	_ = eg.Wait()

	// Merge results back into CompileResult (single-threaded; goroutines are done).
	for _, res := range results {
		if res.resolved {
			for _, ip := range res.ips {
				result.AllowedIPv4.Add(ip)
			}
		} else {
			result.UnresolvedDomains = append(result.UnresolvedDomains, res.domain)
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
