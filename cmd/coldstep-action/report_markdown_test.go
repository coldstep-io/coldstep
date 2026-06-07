package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteDetailedMarkdownReport(t *testing.T) {
	dir := t.TempDir()
	events := filepath.Join(dir, ".coldstep-events.jsonl")
	jsonl := strings.Join([]string{
		`{"type":"tcp","dst":"140.82.121.4","fqdn":"github.com","dport":443}`,
		`{"type":"udp","dst":"8.8.8.8","dport":53}`,
		`{"type":"deny","comm":"curl","protocol":"tcp","dst":"1.2.3.4","dport":443,"reason":"dst_not_allowlisted","hook_family":"cgroup","mode":"defend"}`,
	}, "\n") + "\n"
	if err := os.WriteFile(events, []byte(jsonl), 0o644); err != nil {
		t.Fatalf("write events: %v", err)
	}

	writeDetailedMarkdownReport(dir)

	raw, err := os.ReadFile(filepath.Join(dir, ".coldstep-report.md"))
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	out := string(raw)
	for _, want := range []string{"# coldstep detailed report", "github.com", "## Denies", "curl"} {
		if !strings.Contains(out, want) {
			t.Errorf("report missing %q:\n%s", want, out)
		}
	}
	// Pure markdown — no embedded HTML.
	if strings.Contains(out, "<") {
		t.Errorf("report contains '<' (HTML not allowed):\n%s", out)
	}
}

func TestWriteDetailedMarkdownReport_NoEventsNoFile(t *testing.T) {
	dir := t.TempDir()
	// No .coldstep-events.jsonl present — helper must be a quiet no-op.
	writeDetailedMarkdownReport(dir)
	if _, err := os.Stat(filepath.Join(dir, ".coldstep-report.md")); !os.IsNotExist(err) {
		t.Fatalf("expected no report file when events are absent, stat err=%v", err)
	}
}

func TestStopStrictRequiredTypes(t *testing.T) {
	dir := t.TempDir()
	// Only meta+tcp present — exec missing under the standard profile.
	jsonl := `{"type":"meta"}` + "\n" + `{"type":"tcp","dst":"1.2.3.4","dport":443}` + "\n"
	if err := os.WriteFile(filepath.Join(dir, ".coldstep-events.jsonl"), []byte(jsonl), 0o644); err != nil {
		t.Fatalf("write events: %v", err)
	}
	agg := writeDetailedMarkdownReport(dir)
	if agg == nil {
		t.Fatal("expected aggregate")
	}
	if missing := agg.MissingRequiredTypes(""); len(missing) != 1 || missing[0] != "exec" {
		t.Fatalf("missing = %v want [exec]", missing)
	}
}
