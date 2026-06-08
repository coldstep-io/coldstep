package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestSanitizeDigestForMarkdown_BOM(t *testing.T) {
	// BOM must be stripped
	input := "\uFEFF## heading"
	out := sanitizeDigestForMarkdown(input)
	if strings.Contains(out, "\uFEFF") {
		t.Error("BOM not stripped")
	}
	if !strings.Contains(out, "## heading") {
		t.Errorf("content lost after BOM strip: %q", out)
	}
}

func TestSanitizeDigestForMarkdown_BackslashFirst(t *testing.T) {
	// Backslash must be escaped before backtick/tilde (order-sensitive)
	// If \` is in input, we must get \\` not \\`` which would be wrong
	input := "\\`test"
	out := sanitizeDigestForMarkdown(input)
	// Original backslash escapes first; then ` is a single backtick (not 3), so no fence escaping
	if !strings.Contains(out, "\\\\`") {
		t.Errorf("backslash-first rule violated: got %q", out)
	}
}

func TestSanitizeDigestForMarkdown_FenceBreakout(t *testing.T) {
	// Triple backticks and tildes must be escaped to prevent fence breakout
	cases := []struct {
		input    string
		mustHave string
	}{
		{"```code```", "\\`\\`\\`"},
		{"~~~block~~~", "\\~\\~\\~"},
	}
	for _, c := range cases {
		out := sanitizeDigestForMarkdown(c.input)
		if !strings.Contains(out, c.mustHave) {
			t.Errorf("fence breakout not prevented for %q: got %q", c.input, out)
		}
	}
}

func TestSanitizeDigestForMarkdown_HTMLEntity(t *testing.T) {
	input := "<script>alert(1)</script>"
	out := sanitizeDigestForMarkdown(input)
	if strings.Contains(out, "<script>") {
		t.Errorf("HTML not escaped: got %q", out)
	}
	if !strings.Contains(out, "&lt;") {
		t.Errorf("expected &lt; in output: got %q", out)
	}
}

func TestSanitizeDigestForMarkdown_LineLengthCap(t *testing.T) {
	// Lines over 4096 chars must be truncated
	line := strings.Repeat("x", 5000)
	out := sanitizeDigestForMarkdown(line)
	parts := strings.Split(out, "\n")
	if len(parts[0]) > 4096+len(" ...(truncated)") {
		t.Errorf("line not capped at 4096: len=%d", len(parts[0]))
	}
	if !strings.Contains(parts[0], "...(truncated)") {
		t.Errorf("truncated marker missing: %q", parts[0][:80])
	}
}

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

func TestSanitizeDigestForMarkdown_Empty(t *testing.T) {
	if out := sanitizeDigestForMarkdown(""); out != "" {
		t.Errorf("expected empty output for empty input, got %q", out)
	}
}

func TestSanitizeDigestForMarkdown_CRLFNormalization(t *testing.T) {
	input := "line1\r\nline2\rline3"
	out := sanitizeDigestForMarkdown(input)
	if strings.Contains(out, "\r") {
		t.Errorf("CRLF not normalized: %q", out)
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
	if cfg.DetectProfile != "standard" {
		t.Errorf("expected default detect-profile=standard, got %q", cfg.DetectProfile)
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

// H11: digestIntegrityMarker must produce the canonical hash marker for any
// non-empty body, and yield the empty string for empty / whitespace input so
// runStop does not write a marker against a missing digest file.
func TestDigestIntegrityMarker_RoundTrip(t *testing.T) {
	body := "## Coldstep digest\n\n- exec rows: 4\n"
	got := digestIntegrityMarker(body)
	sum := sha256.Sum256([]byte(body))
	want := fmt.Sprintf("\n<!-- coldstep-digest-sha256: %s -->\n", hex.EncodeToString(sum[:]))
	if got != want {
		t.Fatalf("marker mismatch:\n got %q\nwant %q", got, want)
	}
	if !strings.HasPrefix(got, "\n<!-- coldstep-digest-sha256: ") {
		t.Errorf("marker missing canonical prefix: %q", got)
	}
	if !strings.HasSuffix(got, " -->\n") {
		t.Errorf("marker missing canonical suffix: %q", got)
	}
}

func TestDigestIntegrityMarker_EmptyBodyYieldsNothing(t *testing.T) {
	if got := digestIntegrityMarker(""); got != "" {
		t.Fatalf("expected empty marker for empty body, got %q", got)
	}
	if got := digestIntegrityMarker("   \n\t  "); got != "" {
		t.Fatalf("expected empty marker for whitespace body, got %q", got)
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
