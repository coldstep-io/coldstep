package actioncli

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/coldstep-io/coldstep/internal/config"
)

func TestTruncate_utf8Boundary(t *testing.T) {
	prefix := strings.Repeat("x", 100)
	s := prefix + "€"
	if len(s) != 103 {
		t.Fatalf("unexpected len: %d", len(s))
	}
	out := truncate(s, 101)
	want := prefix + "\n\n_(truncated)_\n"
	if out != want {
		t.Fatalf("truncate broke UTF-8: got %q want %q", out, want)
	}
	if truncate(s, len(s)) != s {
		t.Fatal("truncate noop should return identity")
	}
}

func TestParseStartFlags_Defaults(t *testing.T) {
	cfg, err := parseStartFlags([]string{})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != "detect" {
		t.Errorf("expected default mode=detect, got %q", cfg.Mode)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("expected default log-level=info, got %q", cfg.LogLevel)
	}
	if !cfg.IoUringDisable {
		t.Error("expected io-uring-disable default=true")
	}
	if cfg.FailOnError {
		t.Error("expected fail-on-error default=false")
	}
	// detect-profile parses to "" by design: precedence (flag > env > "standard")
	// is applied once in runStart via config.ResolveDetectProfile, not at the
	// flag-default level. The effective default is still "standard".
	if cfg.DetectProfile != "" {
		t.Errorf("expected parsed detect-profile default=\"\" (resolution deferred), got %q", cfg.DetectProfile)
	}
	if got, err := config.ResolveDetectProfile(cfg.DetectProfile, ""); err != nil || got != "standard" {
		t.Errorf("ResolveDetectProfile(%q, \"\") = %q, %v; want \"standard\", nil", cfg.DetectProfile, got, err)
	}
}

func TestNormalizeCompositeMode(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		raw   string
		want  string
		errOK bool
	}{
		{"", "detect", false},
		{"  ", "detect", false},
		{"Detect", "detect", false},
		{"defend", "defend", false},
		{"DEFEND", "defend", false},
		{"enforce", "", true},
		{"nope", "", true},
	} {
		got, err := normalizeCompositeMode(tc.raw)
		if tc.errOK {
			if err == nil {
				t.Errorf("%q: expected error", tc.raw)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%q: %v", tc.raw, err)
		}
		if got != tc.want {
			t.Errorf("%q: got %q want %q", tc.raw, got, tc.want)
		}
	}
}

func TestParseStartFlags_Explicit(t *testing.T) {
	cfg, err := parseStartFlags([]string{
		"--mode", "defend",
		"--log-level", "debug",
		"--fail-on-error",
		"--io-uring-disable=false",
		"--ready-timeout-seconds", "120",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != "defend" {
		t.Errorf("expected defend, got %q", cfg.Mode)
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("expected debug, got %q", cfg.LogLevel)
	}
	if !cfg.FailOnError {
		t.Error("expected fail-on-error=true")
	}
	if cfg.IoUringDisable {
		t.Error("expected io-uring-disable=false")
	}
	if cfg.ReadyTimeoutSeconds != 120 {
		t.Errorf("expected 120, got %d", cfg.ReadyTimeoutSeconds)
	}
}

func TestParseStartFlags_AllowFile(t *testing.T) {
	cfg, err := parseStartFlags([]string{
		"--allow", "example.com,1.2.3.4",
		"--allow-file", ".github/coldstep/a.txt,.github/coldstep/b.txt",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Allow != "example.com,1.2.3.4" {
		t.Errorf("allow: %q", cfg.Allow)
	}
	if cfg.AllowFile != ".github/coldstep/a.txt,.github/coldstep/b.txt" {
		t.Errorf("allow-file: %q", cfg.AllowFile)
	}
}

func TestParseStopFlags_Defaults(t *testing.T) {
	cfg, err := parseStopFlags([]string{})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Report != "job-summary" {
		t.Errorf("expected report default=job-summary, got %q", cfg.Report)
	}
	jobSummary, prSummary := parseReportFlags(cfg.Report)
	if !jobSummary || prSummary {
		t.Errorf("default report flags: jobSummary=%v prSummary=%v", jobSummary, prSummary)
	}
}

func TestParseReportFlags(t *testing.T) {
	cases := []struct {
		in            string
		jobSum, prSum bool
	}{
		{"", true, false},
		{"job-summary", true, false},
		{"pr-comment", false, true},
		{"both", true, true},
		{"none", false, false},
		{"BOTH", true, true},
		{"unrecognized", true, false},
	}
	for _, c := range cases {
		js, ps := parseReportFlags(c.in)
		if js != c.jobSum || ps != c.prSum {
			t.Errorf("parseReportFlags(%q): got (%v,%v) want (%v,%v)", c.in, js, ps, c.jobSum, c.prSum)
		}
	}
}

func TestClamp(t *testing.T) {
	cases := []struct{ v, lo, hi, want int }{
		{50, 60, 2700, 60},
		{3000, 60, 2700, 2700},
		{1500, 60, 2700, 1500},
	}
	for _, c := range cases {
		got := clamp(c.v, c.lo, c.hi)
		if got != c.want {
			t.Errorf("clamp(%d,%d,%d)=%d want %d", c.v, c.lo, c.hi, got, c.want)
		}
	}
}

func TestTruncate(t *testing.T) {
	s := strings.Repeat("a", 100)
	out := truncate(s, 50)
	if len(out) > 50+len("\n\n_(truncated)_\n") {
		t.Errorf("truncate did not shorten: len=%d", len(out))
	}
	if truncate("short", 100) != "short" {
		t.Error("truncate mutated short string")
	}
}

func TestBoolString(t *testing.T) {
	if boolString(true) != "true" {
		t.Error("expected true")
	}
	if boolString(false) != "false" {
		t.Error("expected false")
	}
}

func TestClassifyReadyStatus(t *testing.T) {
	t.Parallel()
	cases := []struct {
		raw                                   string
		wantReady, wantFail, wantMal, wantInc bool
	}{
		{`{"ok":true}`, true, false, false, false},
		{`{"ok":false}`, false, true, false, false},
		{`{}`, false, false, false, true},
		{"", false, false, true, false},
		{"  \n ", false, false, true, false},
		{`not-json`, false, false, true, false},
		{`{"ok":"no"}`, false, false, true, false}, // non-bool ok → malformed, not explicitFail (Fix 4)
		{`{"ok":null}`, false, false, true, false}, // null ok → malformed, not explicitFail (Fix 4)
	}
	oversized := bytes.Repeat([]byte("x"), maxReadyStatusJSONBytes+1)
	r, f, m, i := classifyReadyStatus(oversized)
	if r || f || i || !m {
		t.Fatalf("classifyReadyStatus(oversized) = (%v,%v,%v,%v) want (false,false,true,false)", r, f, m, i)
	}
	for _, tc := range cases {
		r, f, m, i := classifyReadyStatus([]byte(tc.raw))
		if r != tc.wantReady || f != tc.wantFail || m != tc.wantMal || i != tc.wantInc {
			t.Fatalf("classifyReadyStatus(%q) = (%v,%v,%v,%v) want (%v,%v,%v,%v)",
				tc.raw, r, f, m, i, tc.wantReady, tc.wantFail, tc.wantMal, tc.wantInc)
		}
	}
}

// Bug #8: replace the fixed 400ms post-SIGTERM sleep with a poll loop that
// waits up to the timeout for the agent to exit.
func TestWaitForAgentExit_ReturnsTrueWhenPidGone(t *testing.T) {
	// PID 0 (and negative pids) cannot be alive; the helper short-circuits to
	// false. Use a fake high pid that is overwhelmingly unlikely to be in use.
	const fakePID = 0x6ff7c001
	start := time.Now()
	ok := waitForAgentExit(fakePID, 1*time.Second, 10*time.Millisecond)
	elapsed := time.Since(start)
	if !ok {
		t.Fatalf("waitForAgentExit(fakePID) = false; want true (pid not in use)")
	}
	if elapsed >= 250*time.Millisecond {
		t.Errorf("waitForAgentExit took %s; expected <250ms for a dead pid", elapsed)
	}
}

func TestWaitForAgentExit_RejectsZeroAndNegative(t *testing.T) {
	if waitForAgentExit(0, time.Second, 10*time.Millisecond) {
		t.Errorf("waitForAgentExit(0) = true; want false")
	}
	if waitForAgentExit(-1, time.Second, 10*time.Millisecond) {
		t.Errorf("waitForAgentExit(-1) = true; want false")
	}
	if waitForAgentExit(1234, 0, 10*time.Millisecond) {
		t.Errorf("waitForAgentExit(timeout=0) = true; want false")
	}
}

// Markdown-structure repair (LOW item from the security audit): when the
// truncation cut lands inside a fenced code block, the open fence must be
// closed so the _(truncated)_ marker still renders as Markdown.
func TestTruncate_closesOpenCodeFence(t *testing.T) {
	s := "intro\n```\n" + strings.Repeat("y", 200)
	out := truncate(s, 50)
	if strings.Count(out, "```")%2 != 0 {
		t.Fatalf("expected balanced code fences, got %q", out)
	}
	if !strings.HasSuffix(out, "\n\n_(truncated)_\n") {
		t.Fatalf("missing truncation marker: %q", out)
	}
}

func TestTruncate_balancedFencesUntouched(t *testing.T) {
	s := "a\n```\ncode\n```\n" + strings.Repeat("z", 200)
	out := truncate(s, 20)
	if strings.Count(out, "```")%2 != 0 {
		t.Fatalf("expected balanced code fences, got %q", out)
	}
}

// GHES compatibility (LOW item from the security audit): the PR-comment
// endpoint must honour GITHUB_API_URL so the Bearer token is not sent to
// public GitHub from an Enterprise Server runner, and must refuse non-https
// bases so the token never travels plaintext.
func TestGithubAPIBaseURL(t *testing.T) {
	t.Setenv("GITHUB_API_URL", "")
	got, err := githubAPIBaseURL()
	if err != nil || got != "https://api.github.com" {
		t.Fatalf("default: got %q err %v", got, err)
	}

	t.Setenv("GITHUB_API_URL", "https://ghes.example.corp/api/v3/")
	got, err = githubAPIBaseURL()
	if err != nil || got != "https://ghes.example.corp/api/v3" {
		t.Fatalf("ghes: got %q err %v", got, err)
	}

	t.Setenv("GITHUB_API_URL", "http://ghes.example.corp/api/v3")
	if _, err = githubAPIBaseURL(); err == nil {
		t.Fatal("expected error for plaintext http GITHUB_API_URL")
	}
}
