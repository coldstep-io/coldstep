package policy

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"slices"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"
)

// coldstepDomainAllowlistIPWarnThreshold triggers slog.Warn when one allowlisted domain resolves
// to more than this many distinct addresses of a given family (warn-only; compile outcome unchanged).
const coldstepDomainAllowlistIPWarnThreshold = 10

// coldstepDomainLookupAttemptTimeout caps a single Resolver.LookupIP call so goroutines cannot
// block past the parent compile context (hosted runners / flaky resolvers).
const coldstepDomainLookupAttemptTimeout = 25 * time.Second

// coldstepDomainLookupConcurrencyLimit bounds the number of in-flight DNS
// resolutions across the whole allowlist compile, preventing fork-bomb of
// goroutines for large allowlists (Theme F of the 2026-04-18 review).
//
// Pre-PR-F the code spawned `len(domains)` goroutines unbounded; a defend
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

// IPv6Set stores unique IPv6 addresses in 16-byte form (network byte order
// when serialized). Pure IPv4 inputs are rejected — callers separate AAAA
// resolutions from A resolutions before insertion.
type IPv6Set struct {
	items map[[16]byte]struct{}
}

// Add inserts an IPv6 address into the set. IPv4-mapped IPv6 inputs are
// rejected so the IPv4 and IPv6 sets stay disjoint.
func (s *IPv6Set) Add(ip net.IP) {
	if ip == nil {
		return
	}
	if ip.To4() != nil {
		return
	}
	ip16 := ip.To16()
	if ip16 == nil {
		return
	}
	if s.items == nil {
		s.items = make(map[[16]byte]struct{})
	}
	var key [16]byte
	copy(key[:], ip16)
	s.items[key] = struct{}{}
}

// Contains reports whether ip is present in the set.
func (s IPv6Set) Contains(ip net.IP) bool {
	if ip == nil || len(s.items) == 0 {
		return false
	}
	if ip.To4() != nil {
		return false
	}
	ip16 := ip.To16()
	if ip16 == nil {
		return false
	}
	var key [16]byte
	copy(key[:], ip16)
	_, ok := s.items[key]
	return ok
}

// Len returns the number of unique IPv6 addresses in the set.
func (s IPv6Set) Len() int {
	return len(s.items)
}

// ForEach calls fn for every key in the set.
func (s IPv6Set) ForEach(fn func(k [16]byte)) {
	for k := range s.items {
		fn(k)
	}
}

// CompileResult is the deterministic output from allowlist compilation.
//
// AllowedIPv6 (P2-1 Phase 2) holds AAAA-resolved destinations programmed
// into the BPF allowed_ipv6 LPM trie in defend mode. IPv6 loopback (::1)
// and link-local (fe80::/10) are NOT included here — those bypass
// enforcement directly inside the BPF program.
//
// CompileTimestamp records when CompileDomainAllowlist finished resolving the
// allowlist (H9 DNS-6b). Downstream consumers (digest renderer) compare it to
// time.Now() to surface a TTL-staleness warning on long-running CI jobs.
type CompileResult struct {
	Domains             []string
	AllowedIPv4         IPv4Set
	AllowedIPv6         IPv6Set
	UnresolvedDomains   []string
	WildcardRiskDomains []string
	CompileTimestamp    time.Time
}

// highRiskWildcardSuffixes lists shared-infrastructure DNS suffixes where a
// `*.<suffix>` allowlist entry grants reach to a multi-tenant surface (any
// GitHub-hosted user bucket, any S3 tenant, any Cloudfront/Pages-hosted
// domain). Operators usually want a tighter literal hostname; the wildcard is
// flagged as a "risk" for visibility in the digest, not blocked.
var highRiskWildcardSuffixes = []string{
	".githubusercontent.com",
	".s3.amazonaws.com",
	".blob.core.windows.net",
	".azureedge.net",
	".cloudfront.net",
	".r2.dev",
	".pages.dev",
}

// scoreWildcardRisk returns the subset of domains that are wildcard entries
// (`*.<suffix>`) whose suffix matches one of the known multi-tenant
// shared-infrastructure suffixes. Output preserves input order after the
// caller's normalization. Operators see these in the digest so they can decide
// whether a tighter literal entry would suffice.
func scoreWildcardRisk(domains []string) []string {
	var out []string
	for _, d := range domains {
		if !strings.HasPrefix(d, "*.") {
			continue
		}
		suffix := d[1:] // strip the leading '*', keep the '.'
		for _, risky := range highRiskWildcardSuffixes {
			if strings.EqualFold(suffix, risky) {
				out = append(out, d)
				break
			}
		}
	}
	return out
}

// CompileDomainAllowlist normalizes and resolves domain allowlist entries.
// Resolution is performed concurrently (one goroutine per domain) to avoid
// O(n) sequential latency when defend mode has a large allowlist.
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
		AllowedIPv6: IPv6Set{items: make(map[[16]byte]struct{})},
	}

	type domainResult struct {
		domain    string
		ips4      []net.IP
		ips6      []net.IP
		resolved4 bool
		resolved6 bool
	}

	results := make([]domainResult, len(normalized))

	// errgroup.SetLimit bounds in-flight goroutines to N; Go() blocks on the
	// internal semaphore once N goroutines are running. Workers currently return
	// nil errors (resolution failures land in domainResult.resolved*=false); Wait
	// is still checked so unexpected errgroup failures remain observable in logs.
	// A and AAAA resolutions for the same domain run in the same worker
	// sequentially so the per-domain CPU profile stays predictable; the limit
	// bounds the total in-flight (A or AAAA) lookups across the run.
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
				if !res.resolved4 {
					lookupCtx, cancel := context.WithTimeout(gctx, coldstepDomainLookupAttemptTimeout)
					ips4, err4 := resolver(lookupCtx, "ip4", d)
					cancel()
					// Bug #7: distinguish parent-cancel from per-attempt timeout.
					// Both surface as context.Canceled / context.DeadlineExceeded on err4,
					// but only parent-cancel means "stop retrying"; an attempt-context
					// timeout is exactly the case retries exist for.
					if err4 != nil && (errors.Is(err4, context.Canceled) || errors.Is(err4, context.DeadlineExceeded)) {
						if gctx.Err() != nil {
							break
						}
						// per-attempt deadline fired: fall through to next attempt
					} else if err4 == nil {
						for _, ip := range ips4 {
							if ip.To4() != nil {
								res.ips4 = append(res.ips4, ip)
								res.resolved4 = true
							}
						}
					}
				}
				if !res.resolved6 {
					lookupCtx6, cancel6 := context.WithTimeout(gctx, coldstepDomainLookupAttemptTimeout)
					ips6, err6 := resolver(lookupCtx6, "ip6", d)
					cancel6()
					if err6 != nil && (errors.Is(err6, context.Canceled) || errors.Is(err6, context.DeadlineExceeded)) {
						if gctx.Err() != nil {
							break
						}
						// per-attempt deadline fired: fall through to next attempt
					} else if err6 == nil {
						for _, ip := range ips6 {
							if ip.To4() == nil && ip.To16() != nil {
								res.ips6 = append(res.ips6, ip)
								res.resolved6 = true
							}
						}
					}
				}
				if res.resolved4 && res.resolved6 {
					break
				}
			}
			results[idx] = res
			return nil
		})
	}
	if err := eg.Wait(); err != nil {
		slog.Warn("domain allowlist compile: errgroup wait returned error", "err", err)
	}

	// Merge results back into CompileResult (single-threaded; goroutines are done).
	// A domain is considered "resolved" if either A or AAAA returned at least
	// one address — pure IPv6 destinations remain enforceable without an A
	// record, and pure IPv4 destinations work without AAAA (the common case).
	for _, res := range results {
		resolved := res.resolved4 || res.resolved6
		if !resolved {
			result.UnresolvedDomains = append(result.UnresolvedDomains, res.domain)
			continue
		}
		seen4 := make(map[[4]byte]struct{})
		for _, ip := range res.ips4 {
			ip4 := ip.To4()
			if ip4 == nil {
				continue
			}
			var k [4]byte
			copy(k[:], ip4)
			seen4[k] = struct{}{}
		}
		if len(seen4) > coldstepDomainAllowlistIPWarnThreshold {
			slog.Warn("allowlist domain resolved to many distinct IPv4 addresses (policy ambiguity risk)",
				"domain", res.domain,
				"unique_ipv4", len(seen4),
				"threshold", coldstepDomainAllowlistIPWarnThreshold)
		}
		for _, ip := range res.ips4 {
			result.AllowedIPv4.Add(ip)
		}
		seen6 := make(map[[16]byte]struct{})
		for _, ip := range res.ips6 {
			ip16 := ip.To16()
			if ip16 == nil || ip.To4() != nil {
				continue
			}
			var k [16]byte
			copy(k[:], ip16)
			seen6[k] = struct{}{}
		}
		if len(seen6) > coldstepDomainAllowlistIPWarnThreshold {
			slog.Warn("allowlist domain resolved to many distinct IPv6 addresses (policy ambiguity risk)",
				"domain", res.domain,
				"unique_ipv6", len(seen6),
				"threshold", coldstepDomainAllowlistIPWarnThreshold)
		}
		for _, ip := range res.ips6 {
			result.AllowedIPv6.Add(ip)
		}
	}

	slices.Sort(result.UnresolvedDomains)
	result.WildcardRiskDomains = scoreWildcardRisk(normalized)
	for _, d := range result.WildcardRiskDomains {
		slog.Warn("allowlist: wildcard CDN domain may match unintended hosts", "domain", d)
	}
	result.CompileTimestamp = time.Now()

	slog.Info("allowlist compiled",
		"domains", len(normalized),
		"resolved_ipv4", result.AllowedIPv4.Len(),
		"resolved_ipv6", result.AllowedIPv6.Len(),
		"unresolved_count", len(result.UnresolvedDomains),
		"unresolved", result.UnresolvedDomains,
		"wildcard_risk_count", len(result.WildcardRiskDomains),
	)
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

// NormalizeDomainsFromRaw splits raw on commas/ASCII whitespace, lowercases,
// trims, and dedupes — the canonical entry point for COLDSTEP_ALLOWED_DOMAINS
// and any other comma/space-separated domain list.
func NormalizeDomainsFromRaw(raw string) []string {
	return normalizeAllowlistDomains(splitFields(raw))
}

// ResolveOwners resolves the given domains (A records / IPv4 only) via resolver
// and returns a map of resolved IPv4 address -> owning domain. The owner string
// is the normalized (lowercased, trimmed) domain so it byte-matches the
// allowed_domains BPF map keys; the BPF dns_cache allow-path can then resolve
// dns_cache[ip] -> owner -> allowed_domains[owner].
//
// This is the TRUSTED late-binding source for defend mode: it uses the agent's
// own resolver, NOT DNS responses sniffed from runner traffic. Feeding the BPF
// dns_cache enforcement map from sniffed traffic let a hostile build step poison
// it (craft a fake response mapping an allowlisted FQDN to an attacker IP, then
// egress to that IP). ResolveOwners raises the runtime trust to match the
// startup allowlist-compile trust (same resolver path).
//
// Wildcard entries (`*.suffix`) are skipped — they are not in allowed_domains
// (exact-string map) and are not resolvable. When two domains resolve to the
// same IPv4, the lexicographically smallest owner wins so the result is stable
// across runs. resolver may be nil (defaults to net.DefaultResolver.LookupIP);
// maxAttempts is clamped to >= 1.
func ResolveOwners(ctx context.Context, domains []string, resolver LookupIPFunc, maxAttempts int) map[[4]byte]string {
	if resolver == nil {
		resolver = net.DefaultResolver.LookupIP
	}
	if maxAttempts < 1 {
		maxAttempts = 1
	}
	if ctx == nil {
		ctx = context.Background()
	}
	normalized := normalizeAllowlistDomains(domains)

	type ownerResult struct {
		domain string
		ips4   []net.IP
	}
	results := make([]ownerResult, len(normalized))

	eg, gctx := errgroup.WithContext(ctx)
	eg.SetLimit(coldstepDomainLookupConcurrencyLimit)
	for i, domain := range normalized {
		idx, d := i, domain
		if strings.HasPrefix(d, "*.") {
			continue
		}
		eg.Go(func() error {
			res := ownerResult{domain: d}
			for attempt := 0; attempt < maxAttempts; attempt++ {
				if gctx.Err() != nil {
					break
				}
				lookupCtx, cancel := context.WithTimeout(gctx, coldstepDomainLookupAttemptTimeout)
				ips4, err := resolver(lookupCtx, "ip4", d)
				cancel()
				if err == nil {
					for _, ip := range ips4 {
						if ip.To4() != nil {
							res.ips4 = append(res.ips4, ip)
						}
					}
					break
				}
				if errors.Is(err, context.Canceled) && gctx.Err() != nil {
					break
				}
				// per-attempt timeout or transient failure: retry
			}
			results[idx] = res
			return nil
		})
	}
	if err := eg.Wait(); err != nil {
		slog.Warn("resolve owners: errgroup wait returned error", "err", err)
	}

	out := make(map[[4]byte]string)
	for _, res := range results {
		if res.domain == "" {
			continue
		}
		for _, ip := range res.ips4 {
			ip4 := ip.To4()
			if ip4 == nil {
				continue
			}
			var k [4]byte
			copy(k[:], ip4)
			if existing, ok := out[k]; !ok || res.domain < existing {
				out[k] = res.domain
			}
		}
	}
	return out
}

// DriftReport summarizes the difference between two CompileResult snapshots
// of the same domain allowlist. AddedIPs / RemovedIPs are deterministic
// (sorted ascending) so the caller can emit them in a stable JSONL payload.
//
// H16 DNS allowlist trust hardening: emitted as warning-only telemetry by the
// background re-resolution goroutine in internal/agent. Drift does NOT trigger
// a live BPF policy update — mid-job expansion is intentionally out of scope
// to avoid TOCTOU races where a freshly-resolved CDN tenant IP is added to
// the enforce set between the lookup and the egress attempt.
type DriftReport struct {
	AddedIPs   []string  // dotted-quad IPv4 addresses present in updated but not original
	RemovedIPs []string  // dotted-quad IPv4 addresses present in original but not updated
	CheckedAt  time.Time // wall-clock time the re-resolution finished
}

// ReResolve re-runs CompileDomainAllowlist with the same domain list as
// the original compile and returns the new snapshot for comparison via Diff.
// Concurrency and per-lookup timeout limits match the original compile path
// (set by CompileDomainAllowlist itself via the package-level constants).
// resolver may be nil (defaults to net.DefaultResolver.LookupIP); maxAttempts
// is clamped to ≥1 by CompileDomainAllowlist.
func ReResolve(ctx context.Context, original CompileResult, resolver LookupIPFunc, maxAttempts int) CompileResult {
	return CompileDomainAllowlist(ctx, original.Domains, resolver, maxAttempts)
}

// Diff returns the set difference between original and updated allowlist
// IPv4 resolutions. IPv6 diffing is deferred until H14 lands. Output slices
// are sorted ascending so the resulting DriftReport is byte-stable for
// deterministic JSONL emission. CheckedAt is set to time.Now().
func Diff(original, updated CompileResult) DriftReport {
	added := make([]string, 0)
	removed := make([]string, 0)
	updated.AllowedIPv4.ForEach(func(k [4]byte) {
		if !original.AllowedIPv4.Contains(net.IP(k[:])) {
			added = append(added, net.IP(k[:]).String())
		}
	})
	original.AllowedIPv4.ForEach(func(k [4]byte) {
		if !updated.AllowedIPv4.Contains(net.IP(k[:])) {
			removed = append(removed, net.IP(k[:]).String())
		}
	})
	slices.Sort(added)
	slices.Sort(removed)
	return DriftReport{
		AddedIPs:   added,
		RemovedIPs: removed,
		CheckedAt:  time.Now(),
	}
}
