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

func TestParse_AllowedIPv6LiteralRejected(t *testing.T) {
	_, err := Parse("", "2001:db8::1")
	if err == nil {
		t.Fatal("expected error for IPv6 literal in allowed-ips")
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

func TestParse_AllowedIPv6CIDRRejected(t *testing.T) {
	_, err := Parse("", "2001:db8::/32")
	if err == nil {
		t.Fatal("expected error for IPv6 CIDR in allowed-ips")
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
	if g := p.Classify("example.com", net.IPv4(1, 1, 1, 1)); g != ClassAllowed {
		t.Fatalf("apex should match suffix entry: got %q", g)
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
