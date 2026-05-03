package safepath

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestWorkspace_acceptsPathUnderRunnerTemp(t *testing.T) {
	rt := t.TempDir()
	t.Setenv("GITHUB_WORKSPACE", "")
	t.Setenv("RUNNER_TEMP", rt)
	child := filepath.Join(rt, "agent-status.json")
	if _, err := Workspace(child, "STATUS"); err != nil {
		t.Fatal(err)
	}
}

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
	t.Setenv("TMPDIR", tmp) // Unix: collapse os.TempDir() onto the workspace so a sibling is genuinely outside
	var outside string
	if runtime.GOOS == "windows" {
		// Windows ignores TMPDIR for os.TempDir() (uses %TEMP%/%TMP%); a sibling of t.TempDir()
		// often still lies under the real Temp directory and remains trusted. Use a path under
		// %SystemRoot% which is outside typical workspace/temp/cwd roots for this test layout.
		root := os.Getenv("SystemRoot")
		if root == "" {
			t.Skip("SystemRoot unset")
		}
		outside = filepath.Join(root, "coldstep-safepath-outside-root-test.json")
	} else {
		outside = filepath.Join(filepath.Dir(tmp), "outside.json")
	}
	if _, err := Workspace(outside, "OUT"); err == nil {
		t.Fatal("Workspace: expected error for path outside trusted roots")
	} else if !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("Workspace: expected ErrInvalidPath, got %v", err)
	}
}

func TestWorkspaceRejectsDisallowedCharacters(t *testing.T) {
	if _, err := Workspace("with space.json", "X"); err == nil {
		t.Fatal("Workspace: expected error for disallowed characters")
	} else if !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("Workspace: expected ErrInvalidPath, got %v", err)
	}
	if _, err := Workspace("with;semicolon.json", "X"); err == nil {
		t.Fatal("Workspace: expected error for disallowed characters")
	} else if !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("Workspace: expected ErrInvalidPath, got %v", err)
	}
}

func TestWorkspaceAcceptsNonExistentPathUnderSymlinkedWorkspace(t *testing.T) {
	tmp := t.TempDir()
	realWorkspace := filepath.Join(tmp, "real-workspace")
	if err := os.Mkdir(realWorkspace, 0o755); err != nil {
		t.Fatalf("setup real workspace: %v", err)
	}
	linkWorkspace := filepath.Join(tmp, "workspace-link")
	if err := os.Symlink(realWorkspace, linkWorkspace); err != nil {
		if runtime.GOOS == "windows" {
			t.Skip("workspace symlink requires developer-mode symlink privilege or elevation on Windows:", err)
		}
		t.Fatalf("setup workspace symlink: %v", err)
	}

	t.Setenv("GITHUB_WORKSPACE", linkWorkspace)
	t.Setenv("RUNNER_TEMP", "")
	t.Setenv("TMPDIR", realWorkspace)

	target := filepath.Join(linkWorkspace, "nested", "out.json")
	got, err := Workspace(target, "OUT")
	if err != nil {
		t.Fatalf("Workspace: unexpected error: %v", err)
	}

	want := filepath.Join(realWorkspace, "nested", "out.json")
	if got != want {
		t.Fatalf("Workspace = %q; want %q", got, want)
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
