//go:build !windows

// Windows is not a supported platform for running this repo's Go tests (CI: ubuntu-latest — see README.md).

package report

import "testing"

func TestSanitizeCell(t *testing.T) {
	if g := sanitizeCell("a|b`c\n"); g != "a·b'c" {
		t.Fatalf("got %q want %q", g, "a·b'c")
	}
}
