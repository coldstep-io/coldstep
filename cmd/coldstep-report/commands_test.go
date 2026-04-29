package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDiffSummaryWritesMarker(t *testing.T) {
	tmp := t.TempDir()
	current := filepath.Join(tmp, "current.jsonl")
	baseline := filepath.Join(tmp, "baseline.jsonl")
	summary := filepath.Join(tmp, "summary.md")
	if err := os.WriteFile(current, []byte("{\"type\":\"tcp\",\"dst\":\"1.1.1.1\"}\n"), 0o644); err != nil {
		t.Fatalf("write current: %v", err)
	}
	if err := os.WriteFile(baseline, []byte("{\"type\":\"tcp\",\"dst\":\"8.8.8.8\"}\n"), 0o644); err != nil {
		t.Fatalf("write baseline: %v", err)
	}

	if err := diffSummary([]string{
		"--current=" + current,
		"--baseline=" + baseline,
		"--summary=" + summary,
		"--marker=test-diff",
	}); err != nil {
		t.Fatalf("diffSummary: %v", err)
	}
	raw, err := os.ReadFile(summary)
	if err != nil {
		t.Fatalf("read summary: %v", err)
	}
	if !strings.Contains(string(raw), "test-diff.result=changed") {
		t.Fatalf("summary missing changed marker: %s", string(raw))
	}
}

func TestRenderSummaryAppendsHeader(t *testing.T) {
	tmp := t.TempDir()
	in := writeModelMapFixture(t, tmp, map[string]any{
		"capability_matrix": []any{
			map[string]any{"status": "pass"},
			map[string]any{"status": "fail"},
		},
		"capability_eval": map[string]any{"score": 80, "verdict": "warn"},
		"diff":            map[string]any{"status": "ok", "traffic_new": []any{}, "traffic_gone": []any{}, "traffic_changed": []any{}},
		"otx":             map[string]any{"summary": map[string]any{"malicious": 0, "clean": 1, "unidentified": 0}, "api_calls": 1},
	})
	summary := filepath.Join(tmp, "summary.md")
	if err := renderSummary([]string{"--in=" + in, "--summary=" + summary}); err != nil {
		t.Fatalf("renderSummary: %v", err)
	}
	raw, err := os.ReadFile(summary)
	if err != nil {
		t.Fatalf("read summary: %v", err)
	}
	if !strings.Contains(string(raw), "## Coldstep detect - summary") {
		t.Fatalf("missing summary header: %s", string(raw))
	}
}

func TestRenderHTMLWritesOutput(t *testing.T) {
	tmp := t.TempDir()
	in := writeModelMapFixture(t, tmp, map[string]any{
		"events_by_type":  []any{map[string]any{"type": "tcp", "count": 3}},
		"capability_eval": map[string]any{"score": 100, "verdict": "pass"},
	})
	out := filepath.Join(tmp, "report.html")
	if err := renderHTML([]string{"--in=" + in, "--out=" + out}); err != nil {
		t.Fatalf("renderHTML: %v", err)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read html: %v", err)
	}
	body := string(raw)
	if !strings.Contains(body, "<html>") || !strings.Contains(body, "Coldstep Detect Report") {
		t.Fatalf("unexpected html output: %s", body)
	}
}

func TestRenderIPSummaryIncludesHeading(t *testing.T) {
	tmp := t.TempDir()
	in := writeModelMapFixture(t, tmp, map[string]any{
		"ip_classification": []any{
			map[string]any{"indicator": "1.1.1.1", "kind": "IPv4", "verdict": "clean", "confidence": "B"},
		},
	})
	summary := filepath.Join(tmp, "summary.md")
	if err := renderIPSummary([]string{"--in=" + in, "--summary=" + summary}); err != nil {
		t.Fatalf("renderIPSummary: %v", err)
	}
	raw, err := os.ReadFile(summary)
	if err != nil {
		t.Fatalf("read summary: %v", err)
	}
	if !strings.Contains(string(raw), "## IP Classification Summary") {
		t.Fatalf("missing ip summary heading: %s", string(raw))
	}
}

func TestRDNSEnrichWritesDNSLookupsKey(t *testing.T) {
	tmp := t.TempDir()
	in := writeModelMapFixture(t, tmp, map[string]any{
		"egress_sankey": []any{
			map[string]any{"indicators": []any{"127.0.0.1"}},
		},
	})
	t.Setenv("COLDSTEP_RDNS_WALL_BUDGET_MS", "10")
	if err := rdnsEnrich([]string{"--in=" + in}); err != nil {
		t.Fatalf("rdnsEnrich: %v", err)
	}
	m, err := readModelMap(in)
	if err != nil {
		t.Fatalf("read model: %v", err)
	}
	if _, ok := m["dns_lookups"]; !ok {
		t.Fatalf("dns_lookups key missing after enrichment: %#v", m)
	}
}

func TestOTXEnrichWithoutKeyMarksSkipped(t *testing.T) {
	tmp := t.TempDir()
	in := writeModelMapFixture(t, tmp, map[string]any{
		"egress_sankey": []any{
			map[string]any{"indicators": []any{"1.1.1.1", "example.com"}},
		},
	})
	t.Setenv("OTX_API_KEY", "")
	if err := otxEnrich([]string{"--in=" + in}); err != nil {
		t.Fatalf("otxEnrich: %v", err)
	}
	m, err := readModelMap(in)
	if err != nil {
		t.Fatalf("read model: %v", err)
	}
	otx, ok := m["otx"].(map[string]any)
	if !ok {
		t.Fatalf("otx block missing or wrong type: %#v", m["otx"])
	}
	if skipped, ok := otx["skipped"].(bool); !ok || !skipped {
		t.Fatalf("expected skipped=true, got %#v", otx["skipped"])
	}
}

func writeModelMapFixture(t *testing.T, dir string, payload map[string]any) string {
	t.Helper()
	in := filepath.Join(dir, "model.json")
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	if err := os.WriteFile(in, raw, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return in
}
