// Package releasecheck pins the release-version invariant in `go test ./...`
// so drift is caught locally and in every CI unit job, not only by the
// Python guard scripts (scripts/check_release_version_alignment.py).
//
// Invariant (RELEASE_PROCESS.md "Release invariant", v0.5.2 incident):
// COLDSTEP_BINARY_VERSION in src/shared.ts must equal the version embedded
// in the compiled dist/{pre,main,post}/index.js bundles and the
// MARKETPLACE_COLDSTEP_TAG consumer pin in scripts/check_workflow_action_pins.py.
// A tag placed on a commit violating this ships the previous agent binary
// under the new tag name. The tag-equality leg runs only at release time
// (supply-chain-attest passes --tag to the Python script).
package releasecheck

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// internal/releasecheck/release_alignment_test.go -> repo root.
	return filepath.Dir(filepath.Dir(filepath.Dir(thisFile)))
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

func binaryVersion(t *testing.T, root string) string {
	t.Helper()
	shared := readFile(t, filepath.Join(root, "src", "shared.ts"))
	re := regexp.MustCompile(`(?m)^export const COLDSTEP_BINARY_VERSION = '(v\d+\.\d+\.\d+[^']*)';$`)
	m := re.FindStringSubmatch(shared)
	if m == nil {
		t.Fatal("src/shared.ts: COLDSTEP_BINARY_VERSION declaration not found")
	}
	return m[1]
}

// TestDistBundlesEmbedBinaryVersion fails when src/shared.ts was bumped
// without rebuilding dist/ (stale bundles download the OLD agent).
func TestDistBundlesEmbedBinaryVersion(t *testing.T) {
	root := repoRoot(t)
	version := binaryVersion(t, root)
	for _, rel := range []string{"dist/pre/index.js", "dist/main/index.js", "dist/post/index.js"} {
		path := filepath.Join(root, filepath.FromSlash(rel))
		text := readFile(t, path)
		if !strings.Contains(text, "'"+version+"'") && !strings.Contains(text, `"`+version+`"`) {
			t.Errorf("%s: does not embed COLDSTEP_BINARY_VERSION=%s — run `npm run build` and commit dist/", rel, version)
		}
	}
}

// TestMarketplacePinMatchesBinaryVersion fails when the release PR bumped the
// consumer-facing tag pin (MARKETPLACE_COLDSTEP_TAG) without bumping the agent
// version the action downloads — the exact v0.5.2 packaging bug.
func TestMarketplacePinMatchesBinaryVersion(t *testing.T) {
	root := repoRoot(t)
	version := binaryVersion(t, root)
	pin := readFile(t, filepath.Join(root, "scripts", "check_workflow_action_pins.py"))
	re := regexp.MustCompile(`(?m)^MARKETPLACE_COLDSTEP_TAG = "(v\d+\.\d+\.\d+[^"]*)"$`)
	m := re.FindStringSubmatch(pin)
	if m == nil {
		t.Fatal("scripts/check_workflow_action_pins.py: MARKETPLACE_COLDSTEP_TAG declaration not found")
	}
	if m[1] != version {
		t.Errorf("MARKETPLACE_COLDSTEP_TAG=%s != COLDSTEP_BINARY_VERSION=%s — bump both in the same release PR (RELEASE_PROCESS.md)", m[1], version)
	}
}
