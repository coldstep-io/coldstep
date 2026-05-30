package policy

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
)

func ownerKey(a, b, c, d byte) [4]byte { return [4]byte{a, b, c, d} }

func TestResolveOwners_MapsIPv4ToNormalizedOwner(t *testing.T) {
	resolver := func(_ context.Context, network, host string) ([]net.IP, error) {
		if network != "ip4" {
			t.Fatalf("ResolveOwners must query ip4 only, got %q", network)
		}
		switch host {
		case "example.com":
			return []net.IP{net.ParseIP("93.184.216.34")}, nil
		case "api.example.com":
			return []net.IP{net.ParseIP("203.0.113.7"), net.ParseIP("203.0.113.8")}, nil
		default:
			return nil, errors.New("unexpected host")
		}
	}

	got := ResolveOwners(context.Background(), []string{" Example.COM ", "API.example.com"}, resolver, 2)

	want := map[[4]byte]string{
		ownerKey(93, 184, 216, 34): "example.com",
		ownerKey(203, 0, 113, 7):   "api.example.com",
		ownerKey(203, 0, 113, 8):   "api.example.com",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d entries, want %d (%v)", len(got), len(want), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("owner for %v = %q, want %q", net.IP(k[:]), got[k], v)
		}
	}
}

func TestResolveOwners_SkipsWildcards(t *testing.T) {
	var calls sync.Map
	resolver := func(_ context.Context, _, host string) ([]net.IP, error) {
		calls.Store(host, true)
		return []net.IP{net.ParseIP("10.0.0.1")}, nil
	}
	got := ResolveOwners(context.Background(), []string{"*.cdn.example.com"}, resolver, 1)
	if len(got) != 0 {
		t.Fatalf("wildcard produced %d entries, want 0", len(got))
	}
	if _, ok := calls.Load("*.cdn.example.com"); ok {
		t.Fatalf("wildcard domain must not be resolved")
	}
}

func TestResolveOwners_CollisionPrefersSmallestOwner(t *testing.T) {
	// Two domains resolve to the same IP; the lexicographically smallest owner
	// must win so the seeded map is stable across runs regardless of resolution
	// order.
	resolver := func(_ context.Context, _, host string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("198.51.100.5")}, nil
	}
	got := ResolveOwners(context.Background(), []string{"zebra.example.com", "alpha.example.com"}, resolver, 1)
	if got[ownerKey(198, 51, 100, 5)] != "alpha.example.com" {
		t.Fatalf("collision owner = %q, want alpha.example.com", got[ownerKey(198, 51, 100, 5)])
	}
}

func TestResolveOwners_DropsNonIPv4Results(t *testing.T) {
	resolver := func(_ context.Context, _, _ string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("2606:4700:4700::1111"), net.ParseIP("1.0.0.1")}, nil
	}
	got := ResolveOwners(context.Background(), []string{"one.example.com"}, resolver, 1)
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1 (IPv6 dropped)", len(got))
	}
	if got[ownerKey(1, 0, 0, 1)] != "one.example.com" {
		t.Fatalf("IPv4 owner = %q", got[ownerKey(1, 0, 0, 1)])
	}
}
