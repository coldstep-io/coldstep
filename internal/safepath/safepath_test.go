package safepath

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWorkspaceAcceptsPathsUnderWorkspace(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("GITHUB_WORKSPACE", tmp)
	target := filepath.Join(tmp, "model.json")
	if err := os.WriteFile(target, []byte("{}"), 0o644); err != nil {
		t.Fatalf("setup: %v", err)
	}
	got, err := Workspace(target, "TARGET")
	if err != nil {
		t.Fatalf("Workspace: unexpected error: %v", err)
	}
	want, _ := filepath.EvalSymlinks(target)
	if got != want {
		t.Errorf("Workspace = %q; want %q", got, want)
	}
}

func TestWorkspaceRejectsPathOutsideTrustedRoots(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("GITHUB_WORKSPACE", tmp)
	t.Setenv("RUNNER_TEMP", "")
	t.Setenv("TMPDIR", tmp) // collapse os.TempDir() onto the workspace so a sibling is genuinely outside
	outside := filepath.Join(filepath.Dir(tmp), "outside.json")
	if _, err := Workspace(outside, "OUT"); err == nil {
		t.Fatal("Workspace: expected error for path outside trusted roots")
	}
}

func TestWorkspaceRejectsDisallowedCharacters(t *testing.T) {
	if _, err := Workspace("with space.json", "X"); err == nil {
		t.Fatal("Workspace: expected error for disallowed characters")
	}
	if _, err := Workspace("with;semicolon.json", "X"); err == nil {
		t.Fatal("Workspace: expected error for disallowed characters")
	}
}

func TestWorkspaceFallsBackToCwdWhenWorkspaceUnset(t *testing.T) {
	t.Setenv("GITHUB_WORKSPACE", "")
	t.Setenv("RUNNER_TEMP", "")
	cwd, _ := os.Getwd()
	target := filepath.Join(cwd, "rel-target.json")
	if err := os.WriteFile(target, []byte("{}"), 0o644); err != nil {
		t.Fatalf("setup: %v", err)
	}
	t.Cleanup(func() { os.Remove(target) })
	if _, err := Workspace(target, "X"); err != nil {
		t.Errorf("Workspace fallback: %v", err)
	}
}
