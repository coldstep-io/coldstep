package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var ipv4LiteralOrCIDR = regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$`)

type classifiedAllow struct {
	domains     []string
	hosts       []string
	ips         []string
	ignoredNets []string
}

// classifyAllowTokens splits unified allow-list tokens into per-type buckets.
// Plain or wildcard domains go to both hosts and domains; IPv4 literals/CIDRs
// go to ips; a leading `!` on an IPv4 CIDR routes it to ignoredNets.
func classifyAllowTokens(tokens []string) classifiedAllow {
	var c classifiedAllow
	for _, t := range tokens {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if strings.HasPrefix(t, "!") {
			inner := strings.TrimPrefix(t, "!")
			if ipv4LiteralOrCIDR.MatchString(inner) {
				c.ignoredNets = append(c.ignoredNets, inner)
			}
			continue
		}
		if ipv4LiteralOrCIDR.MatchString(t) {
			c.ips = append(c.ips, t)
		} else {
			c.hosts = append(c.hosts, t)
			c.domains = append(c.domains, t)
		}
	}
	return c
}

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
		// TOCTOU mitigation: verify the symlink still resolves to the same path
		// after reading — if it changed, reject to avoid acting on swapped content.
		full2, err2 := resolvePathUnderWorkspace(wsAbs, rel)
		if err2 != nil || full2 != full {
			return "", fmt.Errorf("allowlist file %q: path changed after read (possible symlink swap)", rel)
		}
		fileTokens = append(fileTokens, parseAllowlistFileBody(body)...)
	}
	inlineTok := splitAllowInlineTokens(inline)
	all := append(append([]string{}, inlineTok...), fileTokens...)
	return strings.Join(all, ","), nil
}

// splitTrimNonEmpty splits s using sep, trims whitespace from each token, and
// drops empty entries. Shared by the comma-path, inline-token, and per-line
// token parsers below; they only differ in which separator runes they accept.
func splitTrimNonEmpty(s string, sep func(r rune) bool) []string {
	parts := strings.FieldsFunc(s, sep)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func splitCommaPaths(csv string) []string {
	return splitTrimNonEmpty(csv, func(r rune) bool { return r == ',' })
}

func splitAllowInlineTokens(inline string) []string {
	return splitTrimNonEmpty(inline, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\n' || r == '\r' || r == '\t'
	})
}

func parseAllowlistFileBody(data []byte) []string {
	lineSep := func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }
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
		out = append(out, splitTrimNonEmpty(line, lineSep)...)
	}
	return out
}

// readBootstrapTokens parses the vendored allowlist file at bootstrapPath.
// Returns nil if the file is missing — older bundles may omit the directory.
func readBootstrapTokens(bootstrapPath string) ([]string, error) {
	body, err := os.ReadFile(bootstrapPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	return parseAllowlistFileBody(body), nil
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
