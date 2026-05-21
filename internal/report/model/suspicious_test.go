package model

import (
	"testing"
)

func TestBuildSuspiciousDomainsFlagsHighEntropyLabel(t *testing.T) {
	// A 16-char base32-ish leftmost label clears the entropy threshold.
	events := []Event{
		{"type": "tls", "ts": "2026-05-18T10:00:00Z", "sni": "abcdefghijklmnop.example.com", "dport": 443},
		{"type": "tls", "ts": "2026-05-18T10:00:01Z", "sni": "abcdefghijklmnop.example.com", "dport": 443},
	}
	rows := BuildSuspiciousDomains(events)
	if len(rows) != 1 {
		t.Fatalf("rows = %d; want 1 (%v)", len(rows), rows)
	}
	if rows[0].Domain != "abcdefghijklmnop.example.com" {
		t.Errorf("domain = %q; want abcdefghijklmnop.example.com", rows[0].Domain)
	}
	if !containsString(rows[0].Reasons, "high_entropy") {
		t.Errorf("reasons = %v; want high_entropy", rows[0].Reasons)
	}
}

func TestBuildSuspiciousDomainsFlagsRareDomain(t *testing.T) {
	events := []Event{
		{"type": "tls", "ts": "2026-05-18T10:00:00Z", "sni": "rare.example.com", "dport": 443},
		{"type": "tls", "ts": "2026-05-18T10:00:01Z", "sni": "common.example.com", "dport": 443},
		{"type": "tls", "ts": "2026-05-18T10:00:02Z", "sni": "common.example.com", "dport": 443},
	}
	rows := BuildSuspiciousDomains(events)
	var rare *SuspiciousDomain
	for i := range rows {
		if rows[i].Domain == "rare.example.com" {
			rare = &rows[i]
		}
	}
	if rare == nil {
		t.Fatalf("rows = %v; want a row for rare.example.com", rows)
	}
	if !containsString(rare.Reasons, "rare") {
		t.Errorf("reasons = %v; want rare", rare.Reasons)
	}
	if rare.Occurrences != 1 {
		t.Errorf("occurrences = %d; want 1", rare.Occurrences)
	}
}

func TestBuildSuspiciousDomainsFlagsPortAnomalyOnHTTPish(t *testing.T) {
	events := []Event{
		{"type": "tls", "ts": "2026-05-18T10:00:00Z", "sni": "weirdport.example.com", "dport": 9999},
		{"type": "tls", "ts": "2026-05-18T10:00:01Z", "sni": "weirdport.example.com", "dport": 9999},
	}
	rows := BuildSuspiciousDomains(events)
	if len(rows) != 1 {
		t.Fatalf("rows = %d; want 1 (%v)", len(rows), rows)
	}
	if !containsString(rows[0].Reasons, "port_anomaly") {
		t.Errorf("reasons = %v; want port_anomaly", rows[0].Reasons)
	}
	if len(rows[0].Ports) == 0 || rows[0].Ports[0] != 9999 {
		t.Errorf("ports = %v; want [9999]", rows[0].Ports)
	}
}

func TestBuildSuspiciousDomainsIgnoresStandardPorts(t *testing.T) {
	events := []Event{
		{"type": "http", "ts": "2026-05-18T10:00:00Z", "host": "api.github.com", "dport": 443},
		{"type": "http", "ts": "2026-05-18T10:00:01Z", "host": "api.github.com", "dport": 443},
		{"type": "tls", "ts": "2026-05-18T10:00:02Z", "sni": "api.github.com", "dport": 443},
	}
	rows := BuildSuspiciousDomains(events)
	if len(rows) != 0 {
		t.Fatalf("rows = %v; want 0 for an ordinary api host on 443", rows)
	}
}

func TestBuildSuspiciousDomainsSkipsBareIPs(t *testing.T) {
	events := []Event{
		{"type": "tcp", "ts": "2026-05-18T10:00:00Z", "dst": "1.2.3.4", "dport": 443},
	}
	rows := BuildSuspiciousDomains(events)
	if len(rows) != 0 {
		t.Fatalf("rows = %v; want 0 — bare IP host has no FQDN", rows)
	}
}

func TestHasHighEntropyLabel(t *testing.T) {
	cases := []struct {
		name   string
		domain string
		want   bool
	}{
		// Known-good (H17 spec): ordinary FQDNs must not trip the DGA heuristic.
		{"plain github", "github.com", false},
		{"api subdomain", "api.example.com", false},
		{"short cdn", "cdn3.example.com", false},
		{"www", "www.example.org", false},
		{"long readable subdomain", "kubernetes-clusters.example.com", false},
		{"empty", "", false},
		{"bare ipv4", "1.2.3.4", false},
		// Known-bad: high-entropy DGA / hex-hash style left-labels.
		{"base32-like 16char", "a3b8c1d9e2f4a1b2.cdn.example.com", true},
		{"long hex 20char", "1a2b3c4d5e6f7890abcd.evil.io", true},
		{"hex hash 16char", "deadbeefcafebabe.example.com", true},
		// Borderline: 11-char label clears entropy but underflows the
		// stricter 12-char DGA floor — should NOT fire here even though
		// the legacy 8-char high_entropy reason might.
		{"borderline 11 char", "abcdefghijk.example.com", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := HasHighEntropyLabel(c.domain)
			if got != c.want {
				t.Fatalf("HasHighEntropyLabel(%q) = %v; want %v", c.domain, got, c.want)
			}
		})
	}
}

func TestBuildSuspiciousDomainsSetsRiskHintAndObservationFields(t *testing.T) {
	events := []Event{
		{"type": "tls", "ts": "2026-05-18T10:00:00Z", "sni": "abcdefghijklmnop.example.com", "dport": 443},
		{"type": "tls", "ts": "2026-05-18T10:00:01Z", "sni": "abcdefghijklmnop.example.com", "dport": 443},
		{"type": "tls", "ts": "2026-05-18T10:00:02Z", "sni": "rare.example.com", "dport": 443},
		{"type": "tls", "ts": "2026-05-18T10:00:03Z", "sni": "common.example.com", "dport": 443},
		{"type": "tls", "ts": "2026-05-18T10:00:04Z", "sni": "common.example.com", "dport": 443},
	}
	rows := BuildSuspiciousDomains(events)

	var dga, rare *SuspiciousDomain
	for i := range rows {
		switch rows[i].Domain {
		case "abcdefghijklmnop.example.com":
			dga = &rows[i]
		case "rare.example.com":
			rare = &rows[i]
		}
	}
	if dga == nil {
		t.Fatalf("rows missing DGA-shaped domain: %v", rows)
	}
	if rare == nil {
		t.Fatalf("rows missing single-observation domain: %v", rows)
	}

	if dga.RiskHint != RiskHintSuspiciousDGA {
		t.Errorf("dga RiskHint = %q; want %q", dga.RiskHint, RiskHintSuspiciousDGA)
	}
	if dga.ObservationCount != 2 {
		t.Errorf("dga ObservationCount = %d; want 2", dga.ObservationCount)
	}
	wantFirst, _ := parseEventTS("2026-05-18T10:00:00Z")
	if !dga.FirstSeenTS.Equal(wantFirst) {
		t.Errorf("dga FirstSeenTS = %v; want %v", dga.FirstSeenTS, wantFirst)
	}
	if rare.RiskHint != RiskHintSingleObservation {
		t.Errorf("rare RiskHint = %q; want %q", rare.RiskHint, RiskHintSingleObservation)
	}
	if rare.ObservationCount != 1 {
		t.Errorf("rare ObservationCount = %d; want 1", rare.ObservationCount)
	}
}

func TestSuspiciousDomainCountsByReason(t *testing.T) {
	rows := []SuspiciousDomain{
		{Domain: "a", Reasons: []string{"high_entropy", "rare"}},
		{Domain: "b", Reasons: []string{"port_anomaly"}},
		{Domain: "c", Reasons: []string{"rare"}},
	}
	he, rare, port := SuspiciousDomainCounts(rows)
	if he != 1 || rare != 2 || port != 1 {
		t.Fatalf("counts = (he=%d, rare=%d, port=%d); want (1,2,1)", he, rare, port)
	}
}
