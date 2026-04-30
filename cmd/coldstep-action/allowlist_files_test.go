package main

import (
	"os"
	"path/filepath"
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

func TestAppendBootstrapTokens(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "boot.txt")
	if err := os.WriteFile(p, []byte("# h\nx.example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := appendBootstrapTokens("a.org", p)
	if err != nil {
		t.Fatal(err)
	}
	if got != "a.org,x.example.com" {
		t.Errorf("got %q", got)
	}
	got2, err := appendBootstrapTokens("a.org", filepath.Join(dir, "missing.txt"))
	if err != nil || got2 != "a.org" {
		t.Errorf("missing file: got %q err %v", got2, err)
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
