package actioncli

import (
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/coldstep-io/coldstep/internal/policy"
)

// maxAllowlistFiles bounds the number of comma-separated allow-file paths a
// single input may name; maxAllowlistFileBytes bounds each file's size
// (mirrors the maxGitHubEventJSONBytes posture — a pathological multi-GiB
// workspace file must not OOM the runner before parsing even starts).
// Realistic allowlists are a few KiB across one or two files.
const (
	maxAllowlistFiles     = 64
	maxAllowlistFileBytes = 8 << 20
)

var ipv4LiteralOrCIDR = regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$`)

// isIPLiteralOrCIDR reports whether t is an IP literal or CIDR — IPv4 or IPv6
// (SP-2). Used to route IP entries to the `ips` bucket (-> COLDSTEP_ALLOWED_IPS
// -> policy.Parse, which programs v4 into allowed_ipv4 and v6 into allowed_ipv6)
// rather than treating an IPv6 literal as a hostname.
func isIPLiteralOrCIDR(t string) bool {
	if ipv4LiteralOrCIDR.MatchString(t) {
		return true
	}
	if strings.Contains(t, "/") {
		_, _, err := net.ParseCIDR(t)
		return err == nil
	}
	return net.ParseIP(t) != nil
}

type classifiedAllow struct {
	domains     []string
	hosts       []string
	ips         []string
	ignoredNets []string
}

// rejectDefendWildcards returns an error if any allow-list host entry uses the
// `*.suffix` wildcard form. Defend mode loads exact hostnames into the BPF
// allowed_domains map (which has no wildcard matching), so a wildcard would be
// silently dropped — subdomains the user expected to be allowed would get
// blocked with no error. Same posture as rejecting `enforce` mode at parse time.
func rejectDefendWildcards(c classifiedAllow) error {
	var bad []string
	seen := make(map[string]struct{})
	for _, list := range [][]string{c.hosts, c.domains} {
		for _, h := range list {
			if strings.HasPrefix(h, "*.") {
				if _, ok := seen[h]; ok {
					continue
				}
				seen[h] = struct{}{}
				bad = append(bad, h)
			}
		}
	}
	if len(bad) == 0 {
		return nil
	}
	return fmt.Errorf("defend mode does not support wildcard allow-list entries (BPF allowed_domains map uses exact-string lookup); replace with exact hostnames or IPv4 literals/CIDRs: %s", strings.Join(bad, ", "))
}

// validateAllowPolicy runs the classified allow buckets through the same parser
// the agent uses, so a malformed entry fails `start` instead of the agent.
//
// classifyAllowTokens routes anything matching ipv4LiteralOrCIDR into `ips`, and
// that regex range-checks neither octets nor prefix length — "10.0.0.256" and
// "1.2.3.4/99" are classified as IPs, not hostnames. policy.Parse rejects them,
// but it only runs inside the `sudo coldstep run` child, long after start has
// returned 0. Unless fail-on-error is set the job then runs to completion with
// no agent attached and nothing in the log saying so (and in defend mode, no
// enforcement). Same reasoning for a `!CIDR` ignore entry that is not a CIDR.
func validateAllowPolicy(c classifiedAllow, noDefaultIgnoredNets bool) error {
	if _, err := policy.BuildPolicyEx(
		strings.Join(c.hosts, ","),
		strings.Join(c.ips, ","),
		strings.Join(c.ignoredNets, ","),
		!noDefaultIgnoredNets,
	); err != nil {
		return fmt.Errorf("allow: %w", err)
	}
	return nil
}

// classifyAllowTokens splits unified allow-list tokens into per-type buckets.
// Plain or wildcard domains go to both hosts and domains; IP literals/CIDRs —
// IPv4 or IPv6 (SP-2) — go to ips; a leading `!` on an IPv4 CIDR routes it to
// ignoredNets (the ignore LPM trie is IPv4-only, so `!IPv6` is not classified).
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
		if isIPLiteralOrCIDR(t) {
			c.ips = append(c.ips, t)
		} else {
			c.hosts = append(c.hosts, t)
			c.domains = append(c.domains, t)
		}
	}
	return c
}

// mergeInlineAndAllowlistFiles concatenates comma-separated workspace-relative (or absolute-under-workspace)
// file paths in filesCSV, reads each text file, parses allowlist tokens (see parseAllowlistFileBody),
// and joins them with inline using comma separation. Empty filesCSV returns inline unchanged.
func mergeInlineAndAllowlistFiles(workspaceRoot, inline, filesCSV string) (string, error) {
	paths := splitCommaPaths(filesCSV)
	if len(paths) == 0 {
		return strings.TrimSpace(inline), nil
	}
	if len(paths) > maxAllowlistFiles {
		return "", fmt.Errorf("allow-file: %d files exceeds maximum %d", len(paths), maxAllowlistFiles)
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
		body, err := readFileCapped(full, maxAllowlistFileBytes)
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

// readFileCapped reads path, rejecting files larger than maxBytes instead of
// loading them. The cap is checked by reading maxBytes+1 through a LimitReader
// rather than trusting a pre-read Stat (which would race with the TOCTOU
// symlink re-check in mergeInlineAndAllowlistFiles).
func readFileCapped(path string, maxBytes int64) ([]byte, error) {
	f, err := os.Open(path) // #nosec G304 -- path containment enforced by resolvePathUnderWorkspace at the call site //nolint:gosec
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("file exceeds maximum size %d bytes", maxBytes)
	}
	return data, nil
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
	// Only a ".." *path element* escapes the workspace. A bare HasPrefix(rel, "..")
	// also rejected in-workspace files whose name merely starts with two dots
	// (e.g. "..allow.txt"). Matches safepath.hasPrefix.
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path outside GITHUB_WORKSPACE")
	}
	return rp, nil
}
