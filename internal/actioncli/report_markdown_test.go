package actioncli

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

func TestRunDiff_NewDomainGate(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GITHUB_WORKSPACE", dir)
	cur := filepath.Join(dir, "cur.jsonl")
	base := filepath.Join(dir, "base.jsonl")
	summary := filepath.Join(dir, "summary.md")
	if err := os.WriteFile(cur, []byte(`{"type":"tcp","fqdn":"evil.example.com","dst":"1.2.3.4","dport":443}`+"\n"), 0o644); err != nil {
		t.Fatalf("write cur: %v", err)
	}
	if err := os.WriteFile(base, []byte(`{"type":"tcp","fqdn":"github.com","dst":"140.82.112.3","dport":443}`+"\n"), 0o644); err != nil {
		t.Fatalf("write base: %v", err)
	}

	// Without the gate: writes marker, returns nil.
	if err := runDiff([]string{"--current=" + cur, "--baseline=" + base, "--summary=" + summary, "--marker=test-diff"}); err != nil {
		t.Fatalf("runDiff: %v", err)
	}
	raw, _ := os.ReadFile(summary)
	if !strings.Contains(string(raw), "test-diff.result=changed") || !strings.Contains(string(raw), "test-diff.new_domains=1") {
		t.Fatalf("summary missing markers:\n%s", raw)
	}

	// With the gate: new domain (evil.example.com) → error.
	err := runDiff([]string{"--current=" + cur, "--baseline=" + base, "--summary=" + summary, "--fail-on-new-domain"})
	if err == nil {
		t.Fatal("expected fail-on-new-domain error")
	}
}

func TestRunAssertIntegrity(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GITHUB_WORKSPACE", dir)
	in := filepath.Join(dir, ".coldstep-events.jsonl")
	// meta+tcp but no exec → standard profile fails.
	if err := os.WriteFile(in, []byte(`{"type":"meta"}`+"\n"+`{"type":"tcp"}`+"\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := runAssertIntegrity([]string{"--in=" + in}); err == nil {
		t.Fatal("expected failure on missing exec")
	}
	// add exec → passes.
	if err := os.WriteFile(in, []byte(`{"type":"meta"}`+"\n"+`{"type":"tcp"}`+"\n"+`{"type":"exec"}`+"\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := runAssertIntegrity([]string{"--in=" + in}); err != nil {
		t.Fatalf("expected pass, got %v", err)
	}
}

func TestWarnRemovedAllowlistInputs_NoPanic(t *testing.T) {
	t.Setenv("INPUT_IGNORED-NETS", "10.0.0.0/8")
	t.Setenv("INPUT_BOOTSTRAP-ALLOWLIST", "true")
	warnRemovedAllowlistInputs() // emits ::warning to stderr; must not panic
	// Unset case: no env → still no panic.
	t.Setenv("INPUT_IGNORED-NETS", "")
	t.Setenv("INPUT_BOOTSTRAP-ALLOWLIST", "")
	warnRemovedAllowlistInputs()
}
