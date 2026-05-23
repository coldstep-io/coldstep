package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseAllowlistFileBody(t *testing.T) {
	raw := `# comment
foo.com, bar.org
  baz.net  
qux.io # tail
`
	got := parseAllowlistFileBody([]byte(raw))
	want := []string{"foo.com", "bar.org", "baz.net", "qux.io"}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("[%d] got %q want %q", i, got[i], want[i])
		}
	}
}

func TestMergeInlineAndAllowlistFiles_NoFiles(t *testing.T) {
	got, err := mergeInlineAndAllowlistFiles("/tmp", "a.com, b.org", "")
	if err != nil {
		t.Fatal(err)
	}
	// No file merge: pass through inline (whitespace preserved; config normalizes later).
	if got != "a.com, b.org" {
		t.Errorf("got %q", got)
	}
}

func TestMergeInlineAndAllowlistFiles_WithFile(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "domains.txt")
	content := "from.file.one\nfrom.file.two\n"
	if err := os.WriteFile(f, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	rel := "domains.txt"
	got, err := mergeInlineAndAllowlistFiles(dir, "inline.domain", rel)
	if err != nil {
		t.Fatal(err)
	}
	if got != "inline.domain,from.file.one,from.file.two" {
		t.Errorf("got %q", got)
	}
}

func TestResolvePathUnderWorkspace_RejectsEscape(t *testing.T) {
	dir := t.TempDir()
	_, err := resolvePathUnderWorkspace(dir, "..")
	if err == nil {
		t.Fatal("expected error for path above workspace")
	}
}

func TestTruthyInput(t *testing.T) {
	for _, s := range []string{"true", "TRUE", "1", "yes"} {
		if !truthyInput(s) {
			t.Errorf("expected true for %q", s)
		}
	}
	for _, s := range []string{"", "false", "0", "no", "banana"} {
		if truthyInput(s) {
			t.Errorf("expected false for %q", s)
		}
	}
}

func TestReadBootstrapTokens(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "boot.txt")
	if err := os.WriteFile(p, []byte("# h\nx.example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := readBootstrapTokens(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "x.example.com" {
		t.Errorf("got %v", got)
	}
	got2, err := readBootstrapTokens(filepath.Join(dir, "missing.txt"))
	if err != nil || got2 != nil {
		t.Errorf("missing file: got %v err %v", got2, err)
	}
}

func TestRejectDefendWildcards(t *testing.T) {
	t.Parallel()

	// No wildcards — accepted in defend mode.
	clean := classifyAllowTokens([]string{"example.com", "api.example.com", "1.2.3.4"})
	if err := rejectDefendWildcards(clean); err != nil {
		t.Fatalf("clean allowlist: unexpected error %v", err)
	}

	// Wildcard entry — must be rejected with a message that names the entry.
	withWild := classifyAllowTokens([]string{"example.com", "*.example.com"})
	err := rejectDefendWildcards(withWild)
	if err == nil {
		t.Fatal("expected error for wildcard entry")
	}
	if !strings.Contains(err.Error(), "*.example.com") {
		t.Errorf("error %q does not name the offending entry", err)
	}
	if !strings.Contains(err.Error(), "defend") {
		t.Errorf("error %q does not mention defend mode", err)
	}

	// Multiple wildcards — each surfaced, no duplicates.
	multi := classifyAllowTokens([]string{"*.a.com", "*.b.com", "*.a.com"})
	err = rejectDefendWildcards(multi)
	if err == nil {
		t.Fatal("expected error for multiple wildcards")
	}
	for _, want := range []string{"*.a.com", "*.b.com"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err, want)
		}
	}
	if strings.Count(err.Error(), "*.a.com") != 1 {
		t.Errorf("expected each wildcard listed once, got %q", err)
	}
}

func TestResolvePathUnderWorkspace_AllowsNested(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "sub", "f.txt")
	if err := os.MkdirAll(filepath.Dir(sub), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sub, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := resolvePathUnderWorkspace(dir, filepath.Join("sub", "f.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(p) != "f.txt" {
		t.Errorf("got %q", p)
	}
}
