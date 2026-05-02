package main

import (
	"bytes"
	"strings"
	"testing"
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
	// Original \ ΓåÆ \\ and then the ` is a single backtick (not 3), so no fence escaping
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
	if len(parts[0]) > 4096+len(" ΓÇª(truncated)") {
		t.Errorf("line not capped at 4096: len=%d", len(parts[0]))
	}
	if !strings.Contains(parts[0], "ΓÇª(truncated)") {
		t.Errorf("truncated marker missing: %q", parts[0][:80])
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

func TestParseStartFlags_AllowlistFiles(t *testing.T) {
	cfg, err := parseStartFlags([]string{
		"--allowed-domains-file", ".github/coldstep/a.txt,.github/coldstep/b.txt",
		"--allowed-ips-file", "policy/extra-ips.txt",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AllowedDomainsFile != ".github/coldstep/a.txt,.github/coldstep/b.txt" {
		t.Errorf("domains file: %q", cfg.AllowedDomainsFile)
	}
	if cfg.AllowedIPsFile != "policy/extra-ips.txt" {
		t.Errorf("ips file: %q", cfg.AllowedIPsFile)
	}
}

func TestParseStartFlags_BootstrapAllowlist(t *testing.T) {
	cfg, err := parseStartFlags([]string{"--bootstrap-allowlist", "true"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.BootstrapAllowlist != "true" {
		t.Errorf("got %q", cfg.BootstrapAllowlist)
	}
}

func TestParseStopFlags_Defaults(t *testing.T) {
	cfg, err := parseStopFlags([]string{})
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.ReportJobSummary {
		t.Error("expected report-job-summary default=true")
	}
	if cfg.ReportPRSummary {
		t.Error("expected report-pr-summary default=false")
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
		{`{"ok":"no"}`, false, true, false, false},
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
