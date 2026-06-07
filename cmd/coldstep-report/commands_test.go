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
		"egress_sankey": []any{
			map[string]any{"source": "github.com", "target": "allowed", "value": 12, "protocol": "tcp", "port": 443, "indicators": []any{"140.82.121.4"}},
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
	if !strings.Contains(string(raw), "## Coldstep — egress baseline") {
		t.Fatalf("missing summary header: %s", string(raw))
	}
}

func TestRenderSummaryShowsProtocolAndPort(t *testing.T) {
	tmp := t.TempDir()
	in := writeModelMapFixture(t, tmp, map[string]any{
		"egress_sankey": []any{
			map[string]any{"source": "github.com", "target": "allowed", "value": 5, "protocol": "tcp", "port": 443, "indicators": []any{"140.82.121.4"}},
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
	if !strings.Contains(body, "tcp") {
		t.Fatalf("missing protocol 'tcp' in summary: %s", body)
	}
	if !strings.Contains(body, "443") {
		t.Fatalf("missing port '443' in summary: %s", body)
	}
}

func TestRenderSummaryWarningForUnidentified(t *testing.T) {
	tmp := t.TempDir()
	in := writeModelMapFixture(t, tmp, map[string]any{
		"egress_sankey": []any{
			map[string]any{"source": "93.184.216.34", "target": "", "value": 3, "protocol": "tcp", "port": 443, "indicators": []any{"93.184.216.34"}},
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
	if !strings.Contains(body, "[!WARNING]") {
		t.Fatalf("missing WARNING alert for unidentified host: %s", body)
	}
	if !strings.Contains(body, "### Unidentified") {
		t.Fatalf("missing Unidentified section: %s", body)
	}
}

func TestRenderSummaryNoWarningWhenAllAllowed(t *testing.T) {
	tmp := t.TempDir()
	in := writeModelMapFixture(t, tmp, map[string]any{
		"egress_sankey": []any{
			map[string]any{"source": "github.com", "target": "allowed", "value": 5, "protocol": "tcp", "port": 443, "indicators": []any{"140.82.121.4"}},
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
	if strings.Contains(body, "[!WARNING]") {
		t.Fatalf("unexpected WARNING alert when all hosts are allowed: %s", body)
	}
	if !strings.Contains(body, "### Allowed") {
		t.Fatalf("missing Allowed section: %s", body)
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
