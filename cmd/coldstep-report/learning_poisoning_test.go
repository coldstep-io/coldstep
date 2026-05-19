package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildModelEmitsObservationHours(t *testing.T) {
	tmp := t.TempDir()
	jsonl := filepath.Join(tmp, "events.jsonl")
	body := `{"type":"meta","ts":"2026-05-18T10:00:00Z"}
{"type":"exec","ts":"2026-05-18T11:00:00Z","comm":"bash"}
{"type":"tcp","ts":"2026-05-18T13:00:00Z","dst":"1.1.1.1"}
`
	if err := os.WriteFile(jsonl, []byte(body), 0o644); err != nil {
		t.Fatalf("setup jsonl: %v", err)
	}
	out := filepath.Join(tmp, "model.json")
	if err := buildModel([]string{"--current=" + jsonl, "--out=" + out}); err != nil {
		t.Fatalf("buildModel: %v", err)
	}
	m := readModelOrFail(t, out)
	if got := floatField(m, "observation_hours"); got < 2.99 || got > 3.01 {
		t.Errorf("observation_hours = %v; want ~3.0", got)
	}
	if _, ok := m["short_observation_window"]; ok {
		// omitempty: when no threshold was supplied, the field should be absent
		t.Errorf("short_observation_window unexpectedly present: %v", m["short_observation_window"])
	}
}

func TestBuildModelFlagsShortObservationWindow(t *testing.T) {
	tmp := t.TempDir()
	jsonl := filepath.Join(tmp, "events.jsonl")
	body := `{"type":"meta","ts":"2026-05-18T10:00:00Z"}
{"type":"tcp","ts":"2026-05-18T10:30:00Z","dst":"1.1.1.1"}
`
	if err := os.WriteFile(jsonl, []byte(body), 0o644); err != nil {
		t.Fatalf("setup jsonl: %v", err)
	}
	out := filepath.Join(tmp, "model.json")
	if err := buildModel([]string{"--current=" + jsonl, "--out=" + out, "--min-observation-hours=24"}); err != nil {
		t.Fatalf("buildModel: %v", err)
	}
	m := readModelOrFail(t, out)
	if got := m["short_observation_window"]; got != true {
		t.Fatalf("short_observation_window = %v; want true", got)
	}
	if got := floatField(m, "min_observation_hours"); got != 24 {
		t.Errorf("min_observation_hours = %v; want 24", got)
	}
}

func TestBuildModelEmitsSuspiciousDomains(t *testing.T) {
	tmp := t.TempDir()
	jsonl := filepath.Join(tmp, "events.jsonl")
	body := `{"type":"meta","ts":"2026-05-18T10:00:00Z"}
{"type":"tls","ts":"2026-05-18T10:00:01Z","sni":"abcdefghijklmnop.example.com","dport":443}
{"type":"tls","ts":"2026-05-18T10:00:02Z","sni":"abcdefghijklmnop.example.com","dport":443}
`
	if err := os.WriteFile(jsonl, []byte(body), 0o644); err != nil {
		t.Fatalf("setup jsonl: %v", err)
	}
	out := filepath.Join(tmp, "model.json")
	if err := buildModel([]string{"--current=" + jsonl, "--out=" + out}); err != nil {
		t.Fatalf("buildModel: %v", err)
	}
	m := readModelOrFail(t, out)
	sd, ok := m["suspicious_domains"].([]any)
	if !ok || len(sd) == 0 {
		t.Fatalf("suspicious_domains missing or empty: %#v", m["suspicious_domains"])
	}
}

func TestAssertIntegrityFailsOnShortObservationWindow(t *testing.T) {
	tmp := t.TempDir()
	in := filepath.Join(tmp, "model.json")
	body := `{"schema_version":"3.0","observation_hours":0.5,"min_observation_hours":24,"short_observation_window":true,"capability_eval":{"verdict":"pass","score":95,"reasons":[]}}`
	if err := os.WriteFile(in, []byte(body), 0o644); err != nil {
		t.Fatalf("setup fixture: %v", err)
	}
	err := assertIntegrity([]string{"--in=" + in})
	if err == nil {
		t.Fatal("err = nil; want short-window fail")
	}
	if !strings.Contains(err.Error(), "short_observation_window") {
		t.Errorf("err = %q; expected short_observation_window marker", err)
	}
}

func TestDiffSummaryFailsOnNewDomain(t *testing.T) {
	tmp := t.TempDir()
	current := filepath.Join(tmp, "current.jsonl")
	baseline := filepath.Join(tmp, "baseline.jsonl")
	summary := filepath.Join(tmp, "summary.md")
	curBody := `{"type":"tls","ts":"2026-05-18T10:00:00Z","sni":"new.evil.example","dport":443,"fqdn":"new.evil.example"}
{"type":"tcp","ts":"2026-05-18T10:00:01Z","dst":"1.1.1.1","fqdn":"api.github.com","dport":443}
`
	baseBody := `{"type":"tcp","ts":"2026-05-18T09:00:00Z","dst":"1.1.1.1","fqdn":"api.github.com","dport":443}
`
	if err := os.WriteFile(current, []byte(curBody), 0o644); err != nil {
		t.Fatalf("setup current: %v", err)
	}
	if err := os.WriteFile(baseline, []byte(baseBody), 0o644); err != nil {
		t.Fatalf("setup baseline: %v", err)
	}

	err := diffSummary([]string{
		"--current=" + current,
		"--baseline=" + baseline,
		"--summary=" + summary,
		"--fail-on-new-domain",
	})
	if err == nil {
		t.Fatal("err = nil; want fail-on-new-domain failure")
	}
	if !strings.Contains(err.Error(), "new destination domain") {
		t.Errorf("err = %q; want new-domain message", err)
	}
	// The summary marker still gets written even on failure.
	raw, readErr := os.ReadFile(summary)
	if readErr != nil {
		t.Fatalf("read summary: %v", readErr)
	}
	if !strings.Contains(string(raw), "new_domains=1") {
		t.Errorf("summary missing new_domains count: %s", string(raw))
	}
}

func TestDiffSummarySucceedsWhenNoNewDomain(t *testing.T) {
	tmp := t.TempDir()
	current := filepath.Join(tmp, "current.jsonl")
	baseline := filepath.Join(tmp, "baseline.jsonl")
	summary := filepath.Join(tmp, "summary.md")
	body := `{"type":"tcp","ts":"2026-05-18T10:00:00Z","dst":"1.1.1.1","fqdn":"api.github.com","dport":443}
`
	if err := os.WriteFile(current, []byte(body), 0o644); err != nil {
		t.Fatalf("setup current: %v", err)
	}
	if err := os.WriteFile(baseline, []byte(body), 0o644); err != nil {
		t.Fatalf("setup baseline: %v", err)
	}
	if err := diffSummary([]string{
		"--current=" + current,
		"--baseline=" + baseline,
		"--summary=" + summary,
		"--fail-on-new-domain",
	}); err != nil {
		t.Fatalf("diffSummary = %v; want nil (no new domains)", err)
	}
}

func TestDiffSummaryNewDomainsIgnoresBareIPs(t *testing.T) {
	tmp := t.TempDir()
	current := filepath.Join(tmp, "current.jsonl")
	baseline := filepath.Join(tmp, "baseline.jsonl")
	summary := filepath.Join(tmp, "summary.md")
	// Current has a new bare-IP destination but no new FQDN -> strict mode
	// should pass. New-domain churn from IP-rotation isn't actionable.
	curBody := `{"type":"tcp","ts":"2026-05-18T10:00:00Z","dst":"9.9.9.9","dport":443}
{"type":"tls","ts":"2026-05-18T10:00:01Z","sni":"api.github.com","dport":443}
`
	baseBody := `{"type":"tls","ts":"2026-05-18T09:00:00Z","sni":"api.github.com","dport":443}
`
	if err := os.WriteFile(current, []byte(curBody), 0o644); err != nil {
		t.Fatalf("setup current: %v", err)
	}
	if err := os.WriteFile(baseline, []byte(baseBody), 0o644); err != nil {
		t.Fatalf("setup baseline: %v", err)
	}
	if err := diffSummary([]string{
		"--current=" + current,
		"--baseline=" + baseline,
		"--summary=" + summary,
		"--fail-on-new-domain",
	}); err != nil {
		t.Fatalf("diffSummary = %v; want nil (new dst is bare IP)", err)
	}
}

func TestRenderSummaryShowsSuspiciousDomainsWarning(t *testing.T) {
	tmp := t.TempDir()
	in := writeModelMapFixture(t, tmp, map[string]any{
		"egress_sankey": []any{
			map[string]any{"source": "abcdefghijklmnop.example.com", "target": "allowed", "value": 2, "protocol": "tls", "port": 443},
		},
		"suspicious_domains": []any{
			map[string]any{"domain": "abcdefghijklmnop.example.com", "reasons": []any{"high_entropy"}, "occurrences": 2},
		},
	})
	summary := filepath.Join(tmp, "summary.md")
	if err := renderSummary([]string{"--in=" + in, "--summary=" + summary}); err != nil {
		t.Fatalf("renderSummary: %v", err)
	}
	raw, err := os.ReadFile(summary)
	if err != nil {
		t.Fatalf("read summary: %v", err)
	}
	body := string(raw)
	if !strings.Contains(body, "suspicious domains flagged") {
		t.Fatalf("summary missing suspicious-domain warning: %s", body)
	}
}

func TestRenderSummaryShowsShortWindowWarning(t *testing.T) {
	tmp := t.TempDir()
	in := writeModelMapFixture(t, tmp, map[string]any{
		"egress_sankey":            []any{map[string]any{"source": "api.github.com", "target": "allowed", "value": 1, "protocol": "tls", "port": 443}},
		"observation_hours":        0.5,
		"min_observation_hours":    24.0,
		"short_observation_window": true,
	})
	summary := filepath.Join(tmp, "summary.md")
	if err := renderSummary([]string{"--in=" + in, "--summary=" + summary}); err != nil {
		t.Fatalf("renderSummary: %v", err)
	}
	raw, err := os.ReadFile(summary)
	if err != nil {
		t.Fatalf("read summary: %v", err)
	}
	if !strings.Contains(string(raw), "Observation window only") {
		t.Fatalf("summary missing short-window warning: %s", string(raw))
	}
}

func readModelOrFail(t *testing.T, path string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read model: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal model: %v", err)
	}
	return m
}

func floatField(m map[string]any, key string) float64 {
	switch v := m[key].(type) {
	case float64:
		return v
	case int:
		return float64(v)
	case int64:
		return float64(v)
	}
	return 0
}
