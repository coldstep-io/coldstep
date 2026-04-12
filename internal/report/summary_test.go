//go:build !windows

// Windows is not a supported platform for running this repo's Go tests (CI: ubuntu-latest — see README.md).

package report

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAppendJobSummary_WritesLine(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "summary.md")
	if err := os.WriteFile(p, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := AppendJobSummary(p, "### CI Guard\n- event a\n"); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "### CI Guard\n- event a\n" {
		t.Fatalf("got %q", string(b))
	}
}

func TestAppendJobSummary_ErrorsWhenPathEmpty(t *testing.T) {
	err := AppendJobSummary("", "x")
	if err == nil {
		t.Fatal("expected error")
	}
}
