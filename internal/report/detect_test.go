//go:build !windows

// Windows is not a supported platform for running this repo's Go tests (CI: ubuntu-latest — see README.md).

package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSanitizeCell(t *testing.T) {
	if g := sanitizeCell("a|b`c\n"); g != "a·b'c" {
		t.Fatalf("got %q want %q", g, "a·b'c")
	}
}

func TestFormatDetectExecRow(t *testing.T) {
	s := FormatDetectExecRow(42, "bash")
	if !strings.Contains(s, "**exec**") || !strings.Contains(s, "`42`") || !strings.Contains(s, "`bash`") {
		t.Fatalf("unexpected row: %s", s)
	}
}

func TestFormatDetectTCPRow(t *testing.T) {
	s := FormatDetectTCPRow(7, "curl", "1.1.1.1", 443, "one.one.one.one", false, "monitor")
	if !strings.Contains(s, "**tcp**") || !strings.Contains(s, "`1.1.1.1:443`") || !strings.Contains(s, "fqdn") || !strings.Contains(s, "monitor") {
		t.Fatalf("unexpected row: %s", s)
	}
	s80 := FormatDetectTCPRow(7, "curl", "10.0.0.1", 80, "", true, "unknown")
	if !strings.Contains(s80, "cleartext-http") || !strings.Contains(s80, "unknown") {
		t.Fatalf("expected cleartext note: %s", s80)
	}
}

func TestAppendDetectRecord_PreambleOnce(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "detect.md")
	row := FormatDetectExecRow(1, "sh")
	if err := AppendDetectRecord(p, row); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	body := string(b)
	if !strings.Contains(body, "## Coldstep") || !strings.Contains(body, "| Event |") || !strings.Contains(body, "| Policy |") {
		t.Fatalf("missing preamble: %s", body)
	}
	if !strings.Contains(body, "| **exec** |") {
		t.Fatalf("missing row: %s", body)
	}
	if err := AppendDetectRecord(p, FormatDetectExecRow(2, "ls")); err != nil {
		t.Fatal(err)
	}
	b2, _ := os.ReadFile(p)
	if c := strings.Count(string(b2), "## Coldstep"); c != 1 {
		t.Fatalf("preamble repeated: count=%d", c)
	}
}
