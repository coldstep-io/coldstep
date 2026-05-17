package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
)

// entryKind classifies a single allowlist token.
type entryKind string

const (
	kindIP             entryKind = "ip"
	kindCIDR           entryKind = "cidr"
	kindDomain         entryKind = "domain"
	kindWildcardDomain entryKind = "wildcard-domain"
	kindNegation       entryKind = "negation"
	kindError          entryKind = "error"
)

// validateEntry classifies a single raw allowlist token and returns any error.
func validateEntry(raw string) (entryKind, error) {
	if strings.HasPrefix(raw, "!") {
		// Negation entries are recognised as a distinct kind; they are not
		// currently supported by the BPF policy engine and are flagged as
		// errors so the operator knows the entry will have no effect.
		return kindNegation, fmt.Errorf("negation entries are not supported: %q", raw)
	}

	if strings.Contains(raw, "/") {
		// CIDR — must be valid IPv4.
		ip, ipNet, err := net.ParseCIDR(raw)
		if err != nil {
			return kindError, fmt.Errorf("invalid CIDR %q: %w", raw, err)
		}
		if ip.To4() == nil {
			return kindError, fmt.Errorf("IPv6 CIDRs are not supported (IPv4 only): %q", raw)
		}
		_ = ipNet
		return kindCIDR, nil
	}

	if ip := net.ParseIP(raw); ip != nil {
		if ip.To4() == nil {
			return kindError, fmt.Errorf("IPv6 addresses are not supported (IPv4 only): %q", raw)
		}
		return kindIP, nil
	}

	// Wildcard domain: "*.example.com"
	if strings.HasPrefix(raw, "*.") {
		suf := strings.TrimPrefix(raw, "*.")
		if suf == "" {
			return kindError, fmt.Errorf("wildcard entry has empty suffix: %q", raw)
		}
		if strings.Contains(suf, "*") {
			return kindError, fmt.Errorf("only a single leading wildcard is allowed: %q", raw)
		}
		if err := validateDomainLabel(suf); err != nil {
			return kindError, fmt.Errorf("invalid wildcard domain %q: %w", raw, err)
		}
		return kindWildcardDomain, nil
	}

	// Plain domain / hostname.
	if err := validateDomainLabel(raw); err != nil {
		return kindError, fmt.Errorf("unrecognised token %q: %w", raw, err)
	}
	return kindDomain, nil
}

// validateDomainLabel checks that s looks like a valid DNS hostname (labels
// separated by dots, each label containing [a-zA-Z0-9-], no leading/trailing
// hyphens). It does not enforce FQDN length limits — that is left to the BPF
// map guard in internal/policy.
func validateDomainLabel(s string) error {
	if s == "" {
		return fmt.Errorf("empty hostname")
	}
	labels := strings.Split(strings.ToLower(s), ".")
	for _, label := range labels {
		if label == "" {
			return fmt.Errorf("hostname %q contains empty label (consecutive dots or leading/trailing dot)", s)
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return fmt.Errorf("hostname label %q has leading or trailing hyphen in %q", label, s)
		}
		for _, ch := range label {
			if !((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-') {
				return fmt.Errorf("hostname %q contains invalid character %q", s, ch)
			}
		}
	}
	return nil
}

// validateResult holds per-entry classification output.
type validateResult struct {
	Line  int
	Raw   string
	Kind  entryKind
	Error error
}

// parseAllowlistLines reads r line by line, strips blank lines and # comments,
// and returns one validateResult per non-blank non-comment token.
func parseAllowlistLines(r io.Reader) []validateResult {
	var results []validateResult
	scanner := bufio.NewScanner(r)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		// Strip inline comment.
		if idx := strings.IndexByte(line, '#'); idx >= 0 {
			line = line[:idx]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		kind, err := validateEntry(line)
		results = append(results, validateResult{
			Line:  lineNum,
			Raw:   line,
			Kind:  kind,
			Error: err,
		})
	}
	return results
}

// runValidate implements the `coldstep validate` subcommand.
// It returns 0 on success (no invalid entries) and 1 if any entry is invalid.
// args is the argument slice starting after "validate" (e.g. ["myfile.txt"]).
func runValidate(args []string, stdout, stderr io.Writer) int {
	var r io.Reader
	var sourceName string

	switch len(args) {
	case 0:
		r = os.Stdin
		sourceName = "<stdin>"
	case 1:
		f, err := os.Open(args[0])
		if err != nil {
			fmt.Fprintf(stderr, "coldstep validate: %v\n", err)
			return 1
		}
		defer f.Close()
		r = f
		sourceName = args[0]
	default:
		fmt.Fprintln(stderr, "usage: coldstep validate [allowlist-file]")
		return 2
	}

	results := parseAllowlistLines(r)

	var counts struct {
		ips       int
		cidrs     int
		domains   int
		wildcards int
		negations int
		errors    int
	}

	for _, res := range results {
		switch res.Kind {
		case kindIP:
			counts.ips++
		case kindCIDR:
			counts.cidrs++
		case kindDomain:
			counts.domains++
		case kindWildcardDomain:
			counts.wildcards++
		case kindNegation:
			counts.negations++
			counts.errors++
			fmt.Fprintf(stdout, "ERROR  line %d: %v\n", res.Line, res.Error)
		case kindError:
			counts.errors++
			fmt.Fprintf(stdout, "ERROR  line %d: %v\n", res.Line, res.Error)
		}
	}

	fmt.Fprintf(stdout, "\n%s: %d IPs, %d CIDRs, %d domains, %d wildcards",
		sourceName, counts.ips, counts.cidrs, counts.domains, counts.wildcards)
	if counts.errors > 0 {
		fmt.Fprintf(stdout, ", %d error(s)\n", counts.errors)
		return 1
	}
	fmt.Fprintln(stdout, " — OK")
	return 0
}
