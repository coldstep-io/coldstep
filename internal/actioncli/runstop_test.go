package actioncli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestWaitForReady_Ready: a status file with ok:true returns "ready".
func TestWaitForReady_Ready(t *testing.T) {
	p := filepath.Join(t.TempDir(), "ready.json")
	if err := os.WriteFile(p, []byte(`{"ok":true}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := waitForReady(p, 2*time.Second, os.Getpid()); got != "ready" {
		t.Fatalf("waitForReady = %q, want ready", got)
	}
}

// TestWaitForReady_ExplicitNotReady: ok:false returns "explicit_not_ready".
func TestWaitForReady_ExplicitNotReady(t *testing.T) {
	p := filepath.Join(t.TempDir(), "ready.json")
	if err := os.WriteFile(p, []byte(`{"ok":false}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := waitForReady(p, 2*time.Second, os.Getpid()); got != "explicit_not_ready" {
		t.Fatalf("waitForReady = %q, want explicit_not_ready", got)
	}
}

// TestWaitForReady_Timeout: no status file + live pid + short budget -> "timeout".
func TestWaitForReady_Timeout(t *testing.T) {
	p := filepath.Join(t.TempDir(), "never-written.json")
	if got := waitForReady(p, 250*time.Millisecond, os.Getpid()); got != "timeout" {
		t.Fatalf("waitForReady = %q, want timeout", got)
	}
}

// TestRunStop_JobSummaryFromJSONL exercises the default report path: the job
// summary is rendered by the markdown generator from .coldstep-events.jsonl
// (the source of truth), not from any agent-written digest.
func TestRunStop_JobSummaryFromJSONL(t *testing.T) {
	ws := t.TempDir()
	action := t.TempDir()
	events := filepath.Join(ws, ".coldstep-events.jsonl")
	const jsonl = `{"type":"meta","ts":"t0","mode":"detect"}
{"type":"tcp","dst":"140.82.112.3","dport":443,"fqdn":"github.com"}
`
	if err := os.WriteFile(events, []byte(jsonl), 0o644); err != nil {
		t.Fatal(err)
	}
	summary := filepath.Join(ws, "step-summary.md")
	if err := os.WriteFile(summary, []byte{}, 0o644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("GITHUB_WORKSPACE", ws)
	t.Setenv("GITHUB_ACTION_PATH", action)
	t.Setenv("GITHUB_STEP_SUMMARY", summary)

	// No pid file present -> runStop skips SIGTERM/drain and proceeds to report.
	if err := runStop(stopConfig{Report: "job-summary"}); err != nil {
		t.Fatalf("runStop: %v", err)
	}

	got, err := os.ReadFile(summary)
	if err != nil {
		t.Fatal(err)
	}
	s := string(got)
	if !strings.Contains(s, "## coldstep") {
		t.Errorf("step summary missing markdown report heading:\n%s", s)
	}
	if !strings.Contains(s, "github.com") {
		t.Errorf("step summary missing observed destination:\n%s", s)
	}

	// The detailed report artifact is written alongside the summary.
	if _, err := os.Stat(filepath.Join(ws, ".coldstep-report.md")); err != nil {
		t.Errorf(".coldstep-report.md not written: %v", err)
	}
}

// TestRunStop_ReportNoneSkipsSummary: report=none must not touch
// GITHUB_STEP_SUMMARY even when a digest exists.
func TestRunStop_ReportNoneSkipsSummary(t *testing.T) {
	ws := t.TempDir()
	action := t.TempDir()
	if err := os.WriteFile(filepath.Join(ws, ".coldstep-events.jsonl"),
		[]byte(`{"type":"meta","ts":"t0","mode":"detect"}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	summary := filepath.Join(ws, "step-summary.md")
	if err := os.WriteFile(summary, []byte("PRE-EXISTING\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("GITHUB_WORKSPACE", ws)
	t.Setenv("GITHUB_ACTION_PATH", action)
	t.Setenv("GITHUB_STEP_SUMMARY", summary)

	if err := runStop(stopConfig{Report: "none"}); err != nil {
		t.Fatalf("runStop: %v", err)
	}

	got, err := os.ReadFile(summary)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got), "Coldstep") {
		t.Errorf("report=none must not write the digest to the step summary:\n%s", got)
	}
}

// TestRunStop_FailOnErrorWithoutReady: fail-on-error with no ready marker and
// no healthy status returns the operational error.
func TestRunStop_FailOnErrorWithoutReady(t *testing.T) {
	ws := t.TempDir()
	action := t.TempDir()
	t.Setenv("GITHUB_WORKSPACE", ws)
	t.Setenv("GITHUB_ACTION_PATH", action)
	t.Setenv("GITHUB_STEP_SUMMARY", "")

	err := runStop(stopConfig{FailOnError: true, Report: "none"})
	if err == nil {
		t.Fatal("runStop with fail-on-error and no ready signal: want error, got nil")
	}
	if !strings.Contains(err.Error(), "did not report ready") {
		t.Fatalf("unexpected error: %v", err)
	}
}
