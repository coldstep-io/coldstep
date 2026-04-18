//go:build !windows

package policy

import (
	"context"
	"errors"
	"net"
	"reflect"
	"testing"
)

func TestCompileDomainAllowlist_NormalizeAndDedupe(t *testing.T) {
	ctx := context.Background()
	calls := map[string]int{}
	resolver := func(_ context.Context, network, host string) ([]net.IP, error) {
		key := network + "|" + host
		calls[key]++
		switch host {
		case "example.com":
			if network == "ip4" {
				return []net.IP{net.ParseIP("1.1.1.1")}, nil
			}
			return nil, nil
		case "api.example.com":
			if network == "ip4" {
				return []net.IP{net.ParseIP("2.2.2.2")}, nil
			}
			return nil, nil
		default:
			return nil, errors.New("unexpected host")
		}
	}

	got := CompileDomainAllowlist(ctx, []string{
		" Example.COM ",
		"api.example.com",
		"example.com",
		"",
		"API.EXAMPLE.COM",
	}, resolver, 2)

	wantDomains := []string{"example.com", "api.example.com"}
	if !reflect.DeepEqual(got.Domains, wantDomains) {
		t.Fatalf("Domains: got %v want %v", got.Domains, wantDomains)
	}
	if len(got.UnresolvedDomains) != 0 {
		t.Fatalf("UnresolvedDomains: got %v want empty", got.UnresolvedDomains)
	}
	if calls["ip4|example.com"] != 1 {
		t.Fatalf("resolver calls example.com: got %v", calls)
	}
	if calls["ip4|api.example.com"] != 1 {
		t.Fatalf("resolver calls api.example.com: got %v", calls)
	}
}

func TestCompileDomainAllowlist_UnresolvedContractAndBoundedRetries(t *testing.T) {
	ctx := context.Background()
	calls := map[string]int{}
	resolver := func(_ context.Context, network, host string) ([]net.IP, error) {
		key := network + "|" + host
		calls[key]++
		switch host {
		case "ok.example.com":
			if network == "ip4" {
				return []net.IP{net.ParseIP("3.3.3.3")}, nil
			}
			return nil, nil
		case "ipv6-only.example.com":
			return nil, nil
		case "down.example.com":
			return nil, errors.New("dns down")
		default:
			return nil, errors.New("unexpected host")
		}
	}

	got := CompileDomainAllowlist(ctx, []string{
		"ok.example.com",
		"ipv6-only.example.com",
		"down.example.com",
	}, resolver, 2)

	if !got.AllowedIPv4.Contains(net.ParseIP("3.3.3.3")) {
		t.Fatal("expected 3.3.3.3 to be present")
	}

	if got.AllowedIPv4.Contains(net.ParseIP("4.4.4.4")) {
		t.Fatal("did not expect 4.4.4.4 to be present")
	}
	wantUnresolved := []string{"down.example.com", "ipv6-only.example.com"}
	if !reflect.DeepEqual(got.UnresolvedDomains, wantUnresolved) {
		t.Fatalf("UnresolvedDomains: got %v want %v", got.UnresolvedDomains, wantUnresolved)
	}
	if calls["ip4|down.example.com"] != 2 {
		t.Fatalf("calls for unresolved domain: got ip4=%d want 2", calls["ip4|down.example.com"])
	}
	if calls["ip4|ok.example.com"] != 1 {
		t.Fatalf("calls for resolved domain ok: got %v", calls)
	}
	if calls["ip4|ipv6-only.example.com"] != 2 {
		t.Fatalf("calls for ipv6-only domain: got %v", calls)
	}
}

func TestIPv4SetContains(t *testing.T) {
	var s IPv4Set
	s.Add(net.ParseIP("1.2.3.4"))
	s.Add(net.ParseIP("5.6.7.8"))
	s.Add(net.ParseIP("2001:db8::1"))

	if !s.Contains(net.ParseIP("1.2.3.4")) {
		t.Fatal("expected 1.2.3.4 to be present")
	}
	if s.Contains(net.ParseIP("1.2.3.5")) {
		t.Fatal("did not expect 1.2.3.5 to be present")
	}
	if s.Contains(net.ParseIP("2001:db8::1")) {
		t.Fatal("did not expect IPv6 to match")
	}
	if s.Contains(nil) {
		t.Fatal("did not expect nil IP to match")
	}
}

func TestCompileDomainAllowlist_ContextCanceledStopsRetries(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	resolver := func(_ context.Context, _ string, _ string) ([]net.IP, error) {
		calls++
		return nil, context.Canceled
	}

	got := CompileDomainAllowlist(ctx, []string{"blocked.example.com"}, resolver, 3)
	if calls != 0 {
		t.Fatalf("resolver calls: got %d want 0 when context is already canceled", calls)
	}
	if !reflect.DeepEqual(got.UnresolvedDomains, []string{"blocked.example.com"}) {
		t.Fatalf("UnresolvedDomains: got %v", got.UnresolvedDomains)
	}
}

func TestCompileDomainAllowlist_MaxAttemptsFloor(t *testing.T) {
	ctx := context.Background()
	calls := 0
	resolver := func(_ context.Context, _ string, _ string) ([]net.IP, error) {
		calls++
		return nil, errors.New("nope")
	}

	_ = CompileDomainAllowlist(ctx, []string{"a.example.com"}, resolver, 0)
	if calls != 1 {
		t.Fatalf("resolver calls: got %d want 1 (ip4 once) when maxAttempts <= 0", calls)
	}
}
