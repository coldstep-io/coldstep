package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func truthyInput(s string) bool {
	v := strings.TrimSpace(strings.ToLower(s))
	return v == "true" || v == "1" || v == "yes"
}

// mergeInlineAndAllowlistFiles concatenates comma-separated workspace-relative (or absolute-under-workspace)
// file paths in filesCSV, reads each text file, parses allowlist tokens (see parseAllowlistFileBody),
// and joins them with inline using comma separation. Empty filesCSV returns inline unchanged.
func mergeInlineAndAllowlistFiles(workspaceRoot, inline, filesCSV string) (string, error) {
	paths := splitCommaPaths(filesCSV)
	if len(paths) == 0 {
		return strings.TrimSpace(inline), nil
	}
	wsAbs, err := filepath.Abs(workspaceRoot)
	if err != nil {
		return "", err
	}
	var fileTokens []string
	for _, rel := range paths {
		full, err := resolvePathUnderWorkspace(wsAbs, rel)
		if err != nil {
			return "", fmt.Errorf("allowlist file %q: %w", rel, err)
		}
		body, err := os.ReadFile(full)
		if err != nil {
			return "", fmt.Errorf("read allowlist file %q: %w", rel, err)
		}
		fileTokens = append(fileTokens, parseAllowlistFileBody(body)...)
	}
	inlineTok := splitAllowInlineTokens(inline)
	all := append(append([]string{}, inlineTok...), fileTokens...)
	return strings.Join(all, ","), nil
}

func splitCommaPaths(csv string) []string {
	s := strings.TrimSpace(csv)
	if s == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func splitAllowInlineTokens(inline string) []string {
	s := strings.TrimSpace(inline)
	if s == "" {
		return nil
	}
	parts := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\n' || r == '\r' || r == '\t'
	})
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseAllowlistFileBody(data []byte) []string {
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		for _, tok := range strings.FieldsFunc(line, func(r rune) bool {
			return r == ',' || r == ' ' || r == '\t'
		}) {
			tok = strings.TrimSpace(tok)
			if tok != "" {
				out = append(out, tok)
			}
		}
	}
	return out
}

// appendBootstrapTokens merges tokens from bootstrapPath into existing comma-separated allowlist.
// If the file is missing, returns existing unchanged (older bundles may omit the directory).
func appendBootstrapTokens(existingCSV, bootstrapPath string) (string, error) {
	body, err := os.ReadFile(bootstrapPath)
	if err != nil {
		if os.IsNotExist(err) {
			return existingCSV, nil
		}
		return "", err
	}
	tok := parseAllowlistFileBody(body)
	if len(tok) == 0 {
		return existingCSV, nil
	}
	prefix := splitAllowInlineTokens(existingCSV)
	all := append(append([]string{}, prefix...), tok...)
	return strings.Join(all, ","), nil
}

func resolvePathUnderWorkspace(workspaceAbs, userPath string) (string, error) {
	workspaceAbs = filepath.Clean(workspaceAbs)
	p := strings.TrimSpace(userPath)
	if p == "" {
		return "", fmt.Errorf("empty path")
	}
	var joined string
	if filepath.IsAbs(p) {
		joined = filepath.Clean(p)
	} else {
		joined = filepath.Join(workspaceAbs, filepath.Clean(p))
	}
	rp, err := filepath.EvalSymlinks(joined)
	if err != nil {
		return "", err
	}
	ws, err := filepath.EvalSymlinks(workspaceAbs)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(ws, rp)
	if err != nil || strings.HasPrefix(rel, "..") {
		return "", fmt.Errorf("path outside GITHUB_WORKSPACE")
	}
	return rp, nil
}
