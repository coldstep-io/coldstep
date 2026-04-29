// Package safepath implements path-traversal hardening for env-var-sourced
// paths read at runtime in untrusted CI input (workflow_dispatch from forks,
// etc.). The combination of a strict regex allowlist + os.path.realpath +
// containment under trusted roots [GITHUB_WORKSPACE, RUNNER_TEMP, os.TempDir,
// os.Getwd] is the same defense the Python pipeline used inline; centralising
// it here lets every subcommand call one helper.
package safepath

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var safePathRE = regexp.MustCompile(`^[A-Za-z0-9_./\\:-]+$`)

// Workspace canonicalises raw via filepath.EvalSymlinks and asserts it
// resolves under one of the trusted roots. varName is used in error messages
// to make CI logs actionable.
func Workspace(raw, varName string) (string, error) {
	if !safePathRE.MatchString(raw) {
		return "", fmt.Errorf("%w: %s contains disallowed characters", ErrInvalidPath, varName)
	}
	resolved, err := filepath.Abs(raw)
	if err != nil {
		return "", fmt.Errorf("%s: %w", varName, err)
	}
	resolved = resolveWithExistingAncestor(resolved)
	roots := trustedRoots()
	for _, r := range roots {
		if hasPrefix(resolved, r) {
			return resolved, nil
		}
	}
	return "", fmt.Errorf("%w: %s resolves outside trusted roots: %q", ErrInvalidPath, varName, resolved)
}

func trustedRoots() []string {
	var out []string
	if ws := os.Getenv("GITHUB_WORKSPACE"); ws != "" {
		if r, err := filepath.EvalSymlinks(ws); err == nil {
			out = append(out, r)
		} else {
			out = append(out, ws)
		}
	}
	if rt := os.Getenv("RUNNER_TEMP"); rt != "" {
		if r, err := filepath.EvalSymlinks(rt); err == nil {
			out = append(out, r)
		} else {
			out = append(out, rt)
		}
	}
	if r, err := filepath.EvalSymlinks(os.TempDir()); err == nil {
		out = append(out, r)
	} else {
		out = append(out, os.TempDir())
	}
	if cwd, err := os.Getwd(); err == nil {
		if r, err := filepath.EvalSymlinks(cwd); err == nil {
			out = append(out, r)
		} else {
			out = append(out, cwd)
		}
	}
	return out
}

func hasPrefix(path, root string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	if rel == "." {
		return true
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return false
	}
	return !filepath.IsAbs(rel)
}

func resolveWithExistingAncestor(path string) string {
	if real, err := filepath.EvalSymlinks(path); err == nil {
		return real
	}

	var suffix []string
	cur := path
	for {
		parent := filepath.Dir(cur)
		if parent == cur {
			return path
		}
		suffix = append(suffix, filepath.Base(cur))
		if realParent, err := filepath.EvalSymlinks(parent); err == nil {
			resolved := realParent
			for i := len(suffix) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, suffix[i])
			}
			return resolved
		}
		cur = parent
	}
}

// ErrInvalidPath is returned when a path fails validation.
var ErrInvalidPath = errors.New("safepath: invalid path")
