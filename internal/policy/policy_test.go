//go:build !windows

// Windows is not a supported platform for running this repo's Go tests (CI: ubuntu-latest — see README.md).

package policy

import (
	"fmt"
	"net"
	"strings"
	"testing"
)

func TestParse_Empty(t *testing.T) {
	p, err := Parse("", "")
	if err != nil {
		t.Fatal(err)
	}
	if p.enabled {
		t.Fatal("expected disabled policy")
	}
	if g := p.Classify("any.com", net.IPv4(1, 1, 1, 1)); g != ClassMonitor {
		t.Fatalf("got %q want monitor", g)
	}
}

// SP-2: IPv6 literals are now accepted and stored as /128 entries for the
// defend allowed_ipv6 LPM trie.
func TestParse_AllowedIPv6Literal(t *testing.T) {
	p, err := Parse("", "2001:db8::1")
	if err != nil {
		t.Fatalf("Parse IPv6 literal: %v", err)
	}
	if len(p.ipv6s) != 1 {
		t.Fatalf("ipv6s = %d want 1", len(p.ipv6s))
	}
	if _, ok := p.ipv6s[string(net.ParseIP("2001:db8::1").To16())]; !ok {
		t.Error("2001:db8::1 not stored in ipv6s")
	}
	if !p.enabled {
		t.Error("policy should be enabled with an IPv6 literal")
	}
	var s IPv6Set
	p.MergeLiteralAllowedIPv6Into(&s)
	if !s.Contains(net.ParseIP("2001:db8::1")) {
		t.Error("MergeLiteralAllowedIPv6Into missed the literal")
	}
}

func TestParse_AllowedIP(t *testing.T) {
	p, err := Parse("", "1.1.1.1, 8.8.8.8")
	if err != nil {
		t.Fatal(err)
	}
	if !p.enabled {
		t.Fatal("expected enabled")
	}
	if g := p.Classify("", net.ParseIP("1.1.1.1")); g != ClassAllowed {
		t.Fatalf("got %q", g)
	}
	if g := p.Classify("", net.ParseIP("9.9.9.9")); g != ClassUnknown {
		t.Fatalf("got %q want unknown", g)
	}
}

func TestParse_AllowedIPv4CIDR(t *testing.T) {
	p, err := Parse("", "203.0.113.0/24, 198.51.100.42")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !p.enabled {
		t.Fatal("expected enabled with mixed IP + CIDR allowlist")
	}
	nets := p.AllowedIPv4Nets()
	if len(nets) != 1 {
		t.Fatalf("expected 1 CIDR allowlist entry, got %d", len(nets))
	}
	if nets[0].String() != "203.0.113.0/24" {
		t.Fatalf("CIDR entry: got %q want 203.0.113.0/24", nets[0].String())
	}
	if g := p.Classify("", net.ParseIP("203.0.113.7")); g != ClassAllowed {
		t.Fatalf("CIDR member 203.0.113.7: got %q want allowed", g)
	}
	if g := p.Classify("", net.ParseIP("198.51.100.42")); g != ClassAllowed {
		t.Fatalf("bare IP 198.51.100.42: got %q want allowed", g)
	}
	if g := p.Classify("", net.ParseIP("203.0.114.1")); g != ClassUnknown {
		t.Fatalf("outside-CIDR 203.0.114.1: got %q want unknown", g)
	}
}

func TestParse_AllowedIPv4CIDRNormalizesHostBitsSetInput(t *testing.T) {
	p, err := Parse("", "203.0.113.42/24")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	nets := p.AllowedIPv4Nets()
	if len(nets) != 1 {
		t.Fatalf("expected 1 CIDR allowlist entry, got %d", len(nets))
	}
	if nets[0].String() != "203.0.113.0/24" {
		t.Fatalf("CIDR entry: got %q want 203.0.113.0/24", nets[0].String())
	}
	if got := p.Classify("", net.ParseIP("203.0.113.99")); got != ClassAllowed {
		t.Fatalf("normalized CIDR should allow member IP: got %q", got)
	}
}

// SP-2: IPv6 CIDRs are now accepted and stored as prefix entries for the defend
// allowed_ipv6 LPM trie.
func TestParse_AllowedIPv6CIDR(t *testing.T) {
	p, err := Parse("", "2001:db8::/32")
	if err != nil {
		t.Fatalf("Parse IPv6 CIDR: %v", err)
	}
	nets := p.AllowedIPv6Nets()
	if len(nets) != 1 {
		t.Fatalf("AllowedIPv6Nets = %d want 1", len(nets))
	}
	if nets[0].String() != "2001:db8::/32" {
		t.Errorf("CIDR = %q want 2001:db8::/32", nets[0].String())
	}
	if !p.enabled {
		t.Error("policy should be enabled with an IPv6 CIDR")
	}
}

// SP-2: a mixed v4/v6 allowlist keeps the families disjoint in the right buckets.
func TestParse_MixedV4V6(t *testing.T) {
	p, err := Parse("", "1.2.3.4, 10.0.0.0/8, 2001:db8::1, 2606:4700::/32")
	if err != nil {
		t.Fatalf("Parse mixed: %v", err)
	}
	if len(p.ips) != 1 || len(p.nets) != 1 {
		t.Errorf("v4: ips=%d nets=%d want 1/1", len(p.ips), len(p.nets))
	}
	if len(p.ipv6s) != 1 || len(p.ipv6nets) != 1 {
		t.Errorf("v6: ipv6s=%d ipv6nets=%d want 1/1", len(p.ipv6s), len(p.ipv6nets))
	}
}

func TestParse_AllowedHostnameTooLong(t *testing.T) {
	long := strings.Repeat("a", MaxAllowedHostnameBytes+1)
	_, err := Parse(long, "")
	if err == nil {
		t.Fatal("expected error for hostname exceeding MaxAllowedHostnameBytes")
	}
}

func TestParse_WildcardSuffixTooLong(t *testing.T) {
	suf := strings.Repeat("b", MaxAllowedHostnameBytes+1)
	_, err := Parse("*."+suf, "")
	if err == nil {
		t.Fatal("expected error for wildcard suffix exceeding MaxAllowedHostnameBytes")
	}
}

func TestParse_ExactHostInvalidCharsRejected(t *testing.T) {
	// Whitespace and commas are already split away by splitFields; the residual
	// vectors are single tokens carrying invalid host bytes (control chars, '=',
	// underscores, shell metacharacters). These can never be valid hostnames and
	// must be rejected up front rather than silently becoming a BPF
	// allowed_domains map key (hardening for the allow-file / allow-input
	// argument-injection finding).
	for _, bad := range []string{"a=b", "under_score.example.com", "host;rm", "a$b", "host\x1bname", "ho`st", "-leadinghyphen.com"} {
		if _, err := Parse(bad, ""); err == nil {
			t.Errorf("expected error for malformed exact host %q", bad)
		}
	}
}

func TestParse_ExactHostValidAccepted(t *testing.T) {
	// Ordinary hostnames, including a single-label host and a root-labelled
	// FQDN (trailing dot), must still parse.
	for _, good := range []string{"example.com", "sub.example.com", "registry-1.docker.io", "localhost", "example.com."} {
		p, err := Parse(good, "")
		if err != nil {
			t.Errorf("expected %q to parse, got %v", good, err)
			continue
		}
		if _, ok := p.exactHosts[strings.ToLower(good)]; !ok {
			t.Errorf("expected %q in exactHosts", good)
		}
	}
}

func TestPolicy_MergeLiteralAllowedIPv4Into(t *testing.T) {
	p, err := Parse("", "1.1.1.1, 8.8.8.8")
	if err != nil {
		t.Fatal(err)
	}
	var s IPv4Set
	p.MergeLiteralAllowedIPv4Into(&s)
	if s.Len() != 2 {
		t.Fatalf("expected 2 IPs in set, got %d", s.Len())
	}
	if !s.Contains(net.ParseIP("8.8.8.8")) {
		t.Fatal("expected 8.8.8.8 in set")
	}
	var nilP *Policy
	nilP.MergeLiteralAllowedIPv4Into(&s) // no panic
}

func TestPolicy_MergeLiteralAllowedIPv4Keys(t *testing.T) {
	p, err := Parse("", "1.1.1.1")
	if err != nil {
		t.Fatal(err)
	}
	keys := make(map[[4]byte]struct{})
	p.MergeLiteralAllowedIPv4Keys(keys)
	want := net.ParseIP("1.1.1.1").To4()
	var wk [4]byte
	copy(wk[:], want)
	if _, ok := keys[wk]; !ok {
		t.Fatalf("expected 1.1.1.1 in keys, got %d entries", len(keys))
	}
	p.MergeLiteralAllowedIPv4Keys(nil) // no panic
	var nilP *Policy
	nilP.MergeLiteralAllowedIPv4Keys(keys) // no panic
}

func TestParse_InvalidIP(t *testing.T) {
	_, err := Parse("", "999.0.0.1")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestParse_ExactHost(t *testing.T) {
	p, err := Parse("example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if g := p.Classify("example.com", net.IPv4(1, 2, 3, 4)); g != ClassAllowed {
		t.Fatalf("got %q", g)
	}
	if g := p.Classify("other.com", net.IPv4(1, 2, 3, 4)); g != ClassNotListed {
		t.Fatalf("got %q want not_listed", g)
	}
}

func TestParse_WildcardHost(t *testing.T) {
	p, err := Parse("*.example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if g := p.Classify("api.example.com", net.IPv4(1, 1, 1, 1)); g != ClassAllowed {
		t.Fatalf("got %q want allowed", g)
	}
	if g := p.Classify("a.b.example.com", net.IPv4(1, 1, 1, 1)); g != ClassNotListed {
		t.Fatalf("got %q want not_listed (multi-level)", g)
	}
	if g := p.Classify("example.com", net.IPv4(1, 1, 1, 1)); g != ClassNotListed {
		t.Fatalf("bare apex must not match wildcard suffix: got %q want not_listed", g)
	}
}

func TestDisplay(t *testing.T) {
	if ClassAllowed.Display() != "allowed" {
		t.Fatal()
	}
	if ClassIgnored.Display() != "ignored" {
		t.Fatalf("got %q", ClassIgnored.Display())
	}
}

func TestBuildPolicy_DefaultIgnoredClassifiesPrivateIP(t *testing.T) {
	p, err := BuildPolicy("", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Classify("", net.ParseIP("10.2.3.4")); got != ClassIgnored {
		t.Fatalf("got %q want ignored", got)
	}
	if got := p.Classify("", net.ParseIP("172.20.1.1")); got != ClassIgnored {
		t.Fatalf("got %q want ignored", got)
	}
	if got := p.Classify("", net.ParseIP("8.8.8.8")); got != ClassMonitor {
		t.Fatalf("got %q want monitor", got)
	}
}

func TestBuildPolicy_UserIgnoredMerged(t *testing.T) {
	p, err := BuildPolicy("", "", "192.168.0.0/16")
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Classify("", net.ParseIP("192.168.1.9")); got != ClassIgnored {
		t.Fatalf("got %q want ignored", got)
	}
	if len(p.IgnoredIPv4Nets()) < 3 {
		t.Fatalf("expected default + user nets, got %d", len(p.IgnoredIPv4Nets()))
	}
}

func TestBuildPolicy_AllowedIPWinsOverIgnored(t *testing.T) {
	p, err := BuildPolicy("", "10.0.0.1", "")
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Classify("", net.ParseIP("10.0.0.1")); got != ClassAllowed {
		t.Fatalf("got %q want allowed", got)
	}
}

func TestParse_NoDefaultIgnored(t *testing.T) {
	p, err := Parse("", "")
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Classify("", net.ParseIP("10.0.0.1")); got != ClassMonitor {
		t.Fatalf("Parse must not attach defaults: got %q", got)
	}
}

func TestBuildPolicyEx_NoDefaultIgnored(t *testing.T) {
	p, err := BuildPolicyEx("", "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Classify("", net.ParseIP("10.0.0.1")); got != ClassMonitor {
		t.Fatalf("got %q want monitor", got)
	}
}

func TestBuildPolicy_TooManyIgnoredNetsRejected(t *testing.T) {
	var parts []string
	for i := 0; i < 127; i++ {
		parts = append(parts, fmt.Sprintf("192.0.2.%d/32", i))
	}
	raw := strings.Join(parts, " ")
	_, err := BuildPolicy("", "", raw)
	if err == nil {
		t.Fatal("expected error: 127 user + 2 default > 128")
	}
	if !strings.Contains(err.Error(), "exceeds maximum") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseIgnoredIPNets_Valid(t *testing.T) {
	nets, err := ParseIgnoredIPNets("10.0.0.0/8, 192.168.1.0/24")
	if err != nil {
		t.Fatal(err)
	}
	got := make(map[string]struct{}, len(nets))
	for _, n := range nets {
		got[n.String()] = struct{}{}
	}
	for _, want := range []string{"10.0.0.0/8", "192.168.1.0/24"} {
		if _, ok := got[want]; !ok {
			t.Fatalf("missing CIDR %q in %v", want, nets)
		}
	}
}

func TestParseIgnoredIPNets_RejectsIPv6(t *testing.T) {
	_, err := ParseIgnoredIPNets("2001:db8::/32")
	if err == nil {
		t.Fatal("expected error for IPv6 CIDR")
	}
}
