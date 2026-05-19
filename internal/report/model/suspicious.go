package model

import (
	"math"
	"sort"
	"strings"
)

// suspiciousReasonHighEntropy etc. are the closed reason set surfaced in
// Report.SuspiciousDomains[].Reasons. Keep these strings stable; consumers
// (render-summary, downstream tooling) match on them.
const (
	suspiciousReasonHighEntropy = "high_entropy"
	suspiciousReasonRare        = "rare"
	suspiciousReasonPortAnomaly = "port_anomaly"
)

// Heuristic thresholds for the P1-2 / 4b learning-mode-poisoning checks.
//
//   - Entropy threshold of 3.5 bits/char on the leftmost DNS label picks
//     up DGA-style subdomains (random base32/base36 strings) while
//     leaving human-readable subdomains alone.
//   - 8-char minimum avoids false-positives on short labels like "api",
//     "www", "cdn3" that can clear the entropy threshold by accident.
const (
	highEntropyMinLabelLen    = 8
	highEntropyMinBitsPerChar = 3.5
)

// standardEgressPorts is the closed allowlist of "common" destination
// ports that do not raise a port_anomaly flag on an HTTP/S-bearing domain.
// Keep this set explicit per CLAUDE.md (3000/8000 included because CI
// workflows commonly stand up local servers there during detect runs).
var standardEgressPorts = map[int]struct{}{
	22:   {},
	25:   {},
	53:   {},
	80:   {},
	443:  {},
	465:  {},
	587:  {},
	3000: {},
	8000: {},
	8080: {},
	8443: {},
}

// domainStats accumulates per-destination evidence for the suspicious-
// domain heuristics. It is keyed by the normalized FQDN/host string.
type domainStats struct {
	occurrences int
	httpish     bool
	ports       map[int]struct{}
}

// BuildSuspiciousDomains scans egress events (tcp, udp, http, tls) and
// returns destinations flagged by any of the P1-2 / 4b heuristics:
//
//   - high_entropy: Shannon entropy of the leftmost DNS label exceeds
//     highEntropyMinBitsPerChar AND label length exceeds
//     highEntropyMinLabelLen.
//   - rare: domain observed exactly once across the entire stream.
//   - port_anomaly: an http/tls observation against the domain on a
//     non-standard port (anything outside standardEgressPorts).
//
// Domains without a printable hostname (IP-only egress) are skipped — the
// entropy check is meaningless on numeric addresses, and rare-IP signal
// is already covered by the egress sankey.
func BuildSuspiciousDomains(events []Event) []SuspiciousDomain {
	stats := map[string]*domainStats{}
	for _, e := range events {
		typ := e.AsString("type")
		if _, ok := egressTypes[typ]; !ok {
			continue
		}
		host := firstNonEmpty(e.AsString("fqdn"), e.AsString("host"), e.AsString("sni"))
		host = strings.TrimSpace(strings.ToLower(host))
		if host == "" {
			continue
		}
		if !looksLikeDomain(host) {
			continue
		}
		s := stats[host]
		if s == nil {
			s = &domainStats{ports: map[int]struct{}{}}
			stats[host] = s
		}
		s.occurrences++
		if typ == "http" || typ == "tls" {
			s.httpish = true
		}
		port := int(e.AsFloat("dport"))
		if port == 0 {
			port = int(e.AsFloat("port"))
		}
		if port > 0 {
			s.ports[port] = struct{}{}
		}
	}

	out := make([]SuspiciousDomain, 0)
	for host, s := range stats {
		reasons := map[string]struct{}{}
		entropy := labelShannonEntropy(host)
		label := leftmostLabel(host)
		if len(label) > highEntropyMinLabelLen && entropy > highEntropyMinBitsPerChar {
			reasons[suspiciousReasonHighEntropy] = struct{}{}
		}
		if s.occurrences == 1 {
			reasons[suspiciousReasonRare] = struct{}{}
		}
		if s.httpish {
			for p := range s.ports {
				if _, ok := standardEgressPorts[p]; !ok {
					reasons[suspiciousReasonPortAnomaly] = struct{}{}
					break
				}
			}
		}
		if len(reasons) == 0 {
			continue
		}
		sd := SuspiciousDomain{
			Domain:      host,
			Reasons:     sortedKeys(reasons),
			Occurrences: s.occurrences,
		}
		if _, ok := reasons[suspiciousReasonHighEntropy]; ok {
			sd.Entropy = roundTo(entropy, 4)
		}
		if _, ok := reasons[suspiciousReasonPortAnomaly]; ok {
			sd.Ports = sortedPorts(s.ports)
		}
		out = append(out, sd)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Domain < out[j].Domain })
	return out
}

func leftmostLabel(host string) string {
	if i := strings.IndexByte(host, '.'); i >= 0 {
		return host[:i]
	}
	return host
}

// labelShannonEntropy returns the Shannon entropy in bits/char of the
// leftmost DNS label. Returns 0 when the label is empty.
func labelShannonEntropy(host string) float64 {
	label := leftmostLabel(host)
	if label == "" {
		return 0
	}
	counts := map[rune]int{}
	total := 0
	for _, r := range label {
		counts[r]++
		total++
	}
	if total == 0 {
		return 0
	}
	var h float64
	for _, c := range counts {
		p := float64(c) / float64(total)
		h -= p * math.Log2(p)
	}
	return h
}

// looksLikeDomain rejects bare IPv4 / IPv6 literals so the entropy check
// is not applied to numeric addresses. We accept any string containing
// at least one non-digit, non-separator rune (covers FQDNs, wildcard
// hosts like *.svc, and local hosts like "registry"); pure-numeric input
// like "1.2.3.4" is rejected.
func looksLikeDomain(host string) bool {
	if host == "" {
		return false
	}
	for _, r := range host {
		if r == '.' || r == '-' {
			continue
		}
		if r >= '0' && r <= '9' {
			continue
		}
		return true
	}
	return false
}

func sortedKeys(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedPorts(set map[int]struct{}) []int {
	out := make([]int, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Ints(out)
	return out
}

func roundTo(f float64, places int) float64 {
	pow := math.Pow(10, float64(places))
	return math.Round(f*pow) / pow
}

// SuspiciousDomainCounts breaks down a SuspiciousDomain slice by reason
// for human-readable summary output. Each domain contributes once per
// reason it carries.
func SuspiciousDomainCounts(rows []SuspiciousDomain) (highEntropy, rare, portAnomaly int) {
	for _, r := range rows {
		for _, reason := range r.Reasons {
			switch reason {
			case suspiciousReasonHighEntropy:
				highEntropy++
			case suspiciousReasonRare:
				rare++
			case suspiciousReasonPortAnomaly:
				portAnomaly++
			}
		}
	}
	return
}
