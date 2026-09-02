package actioncli

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

// TestClassifyAllowTokens_IgnoreRouting is the SP-1 invariant: a leading `!`
// CIDR in the allow list routes to ignoredNets (the only ignore mechanism after
// removing the ignored-nets input), while plain entries classify normally.
func TestClassifyAllowTokens_IgnoreRouting(t *testing.T) {
	c := classifyAllowTokens([]string{"example.com", "1.2.3.4", "!10.0.0.0/8", "!172.16.0.0/12"})
	if len(c.ignoredNets) != 2 || c.ignoredNets[0] != "10.0.0.0/8" || c.ignoredNets[1] != "172.16.0.0/12" {
		t.Fatalf("ignoredNets = %v want [10.0.0.0/8 172.16.0.0/12]", c.ignoredNets)
	}
	if len(c.ips) != 1 || c.ips[0] != "1.2.3.4" {
		t.Fatalf("ips = %v want [1.2.3.4]", c.ips)
	}
	if len(c.domains) != 1 || c.domains[0] != "example.com" {
		t.Fatalf("domains = %v want [example.com]", c.domains)
	}
}

// Allow-file resource caps (LOW item from the security audit): an oversized
// workspace file or a sprawling comma list of paths must be rejected before
// the contents are loaded, not parsed into OOM.
func TestMergeInlineAndAllowlistFiles_FileTooLargeRejected(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "big.txt")
	if err := os.WriteFile(f, make([]byte, maxAllowlistFileBytes+1), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := mergeInlineAndAllowlistFiles(dir, "", "big.txt")
	if err == nil {
		t.Fatal("expected error for allow-file exceeding maxAllowlistFileBytes")
	}
	if !strings.Contains(err.Error(), "maximum size") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestMergeInlineAndAllowlistFiles_FileAtCapAccepted(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "ok.txt")
	body := []byte("a.example.com\n")
	if err := os.WriteFile(f, body, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := mergeInlineAndAllowlistFiles(dir, "", "ok.txt")
	if err != nil {
		t.Fatal(err)
	}
	if got != "a.example.com" {
		t.Errorf("got %q", got)
	}
}

func TestMergeInlineAndAllowlistFiles_TooManyFilesRejected(t *testing.T) {
	dir := t.TempDir()
	var paths []string
	for i := 0; i <= maxAllowlistFiles; i++ {
		paths = append(paths, "f.txt")
	}
	_, err := mergeInlineAndAllowlistFiles(dir, "", strings.Join(paths, ","))
	if err == nil {
		t.Fatal("expected error for too many allow-file paths")
	}
	if !strings.Contains(err.Error(), "maximum") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// A file whose name merely starts with two dots is inside the workspace. The
// escape check used a bare HasPrefix(rel, "..") and rejected it.
func TestResolvePathUnderWorkspace_AllowsDotDotPrefixedName(t *testing.T) {
	ws := t.TempDir()
	want := filepath.Join(ws, "..allow.txt")
	if err := os.WriteFile(want, []byte("example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := resolvePathUnderWorkspace(ws, "..allow.txt")
	if err != nil {
		t.Fatalf("resolvePathUnderWorkspace(..allow.txt) = %v, want it accepted", err)
	}
	realWant, err := filepath.EvalSymlinks(want)
	if err != nil {
		t.Fatal(err)
	}
	if got != realWant {
		t.Errorf("got %q want %q", got, realWant)
	}
}

// ".." as a whole element must still be rejected.
func TestResolvePathUnderWorkspace_RejectsDotDotElement(t *testing.T) {
	ws := t.TempDir()
	if _, err := resolvePathUnderWorkspace(ws, filepath.Join("..", "escape.txt")); err == nil {
		t.Error("resolvePathUnderWorkspace accepted a '..' traversal")
	}
}

// A malformed literal must fail `start`, not the sudo child. ipv4LiteralOrCIDR
// range-checks neither octets nor prefix length, so these are classified as IPs.
func TestValidateAllowPolicy_RejectsMalformedEntries(t *testing.T) {
	for _, tok := range []string{"10.0.0.256", "1.2.3.4/99", "999.999.999.999", "!10.0.0.1"} {
		c := classifyAllowTokens([]string{tok})
		if err := validateAllowPolicy(c, false); err == nil {
			t.Errorf("validateAllowPolicy(%q) = nil, want an error (ips=%v ignoredNets=%v)", tok, c.ips, c.ignoredNets)
		}
	}
}

func TestValidateAllowPolicy_AcceptsWellFormed(t *testing.T) {
	c := classifyAllowTokens([]string{"github.com", "*.githubusercontent.com", "10.1.2.3", "192.0.2.0/24", "2001:db8::1", "!172.16.0.0/12"})
	if err := validateAllowPolicy(c, false); err != nil {
		t.Fatalf("validateAllowPolicy on a well-formed allow list: %v", err)
	}
}
