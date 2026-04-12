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
