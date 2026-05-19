//go:build !windows

package policy

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"reflect"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
)

func bumpCallCount(cm *sync.Map, key string) {
	actual, _ := cm.LoadOrStore(key, new(atomic.Int64))
	actual.(*atomic.Int64).Add(1)
}

func loadCallCount(cm *sync.Map, key string) int64 {
	v, ok := cm.Load(key)
	if !ok {
		return 0
	}
	return v.(*atomic.Int64).Load()
}

func TestCompileDomainAllowlist_NormalizeAndDedupe(t *testing.T) {
	ctx := context.Background()
	var calls sync.Map
	resolver := func(_ context.Context, network, host string) ([]net.IP, error) {
		key := network + "|" + host
		bumpCallCount(&calls, key)
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
	if loadCallCount(&calls, "ip4|example.com") != 1 {
		t.Fatalf("resolver calls example.com: got %v", loadCallCount(&calls, "ip4|example.com"))
	}
	if loadCallCount(&calls, "ip4|api.example.com") != 1 {
		t.Fatalf("resolver calls api.example.com: got %v", loadCallCount(&calls, "ip4|api.example.com"))
	}
}

func TestCompileDomainAllowlist_UnresolvedContractAndBoundedRetries(t *testing.T) {
	ctx := context.Background()
	var calls sync.Map
	resolver := func(_ context.Context, network, host string) ([]net.IP, error) {
		key := network + "|" + host
		bumpCallCount(&calls, key)
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
	if loadCallCount(&calls, "ip4|down.example.com") != 2 {
		t.Fatalf("calls for unresolved domain: got ip4=%d want 2", loadCallCount(&calls, "ip4|down.example.com"))
	}
	if loadCallCount(&calls, "ip4|ok.example.com") != 1 {
		t.Fatalf("calls for resolved domain ok: got %v", loadCallCount(&calls, "ip4|ok.example.com"))
	}
	if loadCallCount(&calls, "ip4|ipv6-only.example.com") != 2 {
		t.Fatalf("calls for ipv6-only domain: got %v", loadCallCount(&calls, "ip4|ipv6-only.example.com"))
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
	// P2-1 Phase 2: compile resolves A and AAAA; maxAttempts floor of 1
	// means one ip4 attempt + one ip6 attempt = 2 resolver calls per domain.
	if calls != 2 {
		t.Fatalf("resolver calls: got %d want 2 (ip4 + ip6 once each) when maxAttempts <= 0", calls)
	}
}

func TestScoreWildcardRisk(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{name: "empty", in: nil, want: nil},
		{name: "no wildcards", in: []string{"github.com", "api.github.com"}, want: nil},
		{name: "non-risky wildcard", in: []string{"*.example.org"}, want: nil},
		{name: "githubusercontent", in: []string{"*.githubusercontent.com"}, want: []string{"*.githubusercontent.com"}},
		{name: "s3 amazonaws", in: []string{"*.s3.amazonaws.com"}, want: []string{"*.s3.amazonaws.com"}},
		{
			name: "azure + cdn",
			in:   []string{"*.blob.core.windows.net", "*.azureedge.net"},
			want: []string{"*.blob.core.windows.net", "*.azureedge.net"},
		},
		{
			name: "cloudfront + r2 + pages",
			in:   []string{"*.cloudfront.net", "*.r2.dev", "*.pages.dev"},
			want: []string{"*.cloudfront.net", "*.r2.dev", "*.pages.dev"},
		},
		{
			name: "mixed",
			in:   []string{"api.github.com", "*.cloudfront.net", "*.example.org", "*.s3.amazonaws.com"},
			want: []string{"*.cloudfront.net", "*.s3.amazonaws.com"},
		},
		{name: "case-insensitive suffix match", in: []string{"*.S3.AMAZONAWS.COM"}, want: []string{"*.S3.AMAZONAWS.COM"}},
		{name: "non-risky wildcard suffix", in: []string{"*.internal.corp"}, want: nil},
		{name: "literal host on shared suffix is not flagged", in: []string{"foo.s3.amazonaws.com"}, want: nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := scoreWildcardRisk(tc.in)
			if !slices.Equal(got, tc.want) {
				t.Fatalf("scoreWildcardRisk(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestCompileDomainAllowlist_PopulatesWildcardRiskDomains(t *testing.T) {
	ctx := context.Background()
	resolver := func(_ context.Context, _, _ string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("9.9.9.9")}, nil
	}
	got := CompileDomainAllowlist(ctx,
		[]string{"api.github.com", "*.s3.amazonaws.com", "*.example.org"},
		resolver, 1)
	want := []string{"*.s3.amazonaws.com"}
	if !slices.Equal(got.WildcardRiskDomains, want) {
		t.Fatalf("WildcardRiskDomains: got %v want %v", got.WildcardRiskDomains, want)
	}
}

func TestCompileDomainAllowlist_ResolvesAAAA(t *testing.T) {
	ctx := context.Background()
	var calls sync.Map
	resolver := func(_ context.Context, network, host string) ([]net.IP, error) {
		bumpCallCount(&calls, network+"|"+host)
		switch host {
		case "v6-only.example.com":
			if network == "ip6" {
				return []net.IP{net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2")}, nil
			}
			return nil, nil
		case "dual-stack.example.com":
			if network == "ip4" {
				return []net.IP{net.ParseIP("1.2.3.4")}, nil
			}
			return []net.IP{net.ParseIP("2606:4700::1")}, nil
		default:
			return nil, errors.New("unexpected host")
		}
	}

	got := CompileDomainAllowlist(ctx, []string{"v6-only.example.com", "dual-stack.example.com"}, resolver, 2)

	if got.AllowedIPv6.Len() != 3 {
		t.Fatalf("AllowedIPv6.Len()=%d want 3 (2 v6-only + 1 dual-stack)", got.AllowedIPv6.Len())
	}
	if !got.AllowedIPv6.Contains(net.ParseIP("2001:db8::1")) {
		t.Fatal("expected 2001:db8::1 in AllowedIPv6")
	}
	if !got.AllowedIPv6.Contains(net.ParseIP("2606:4700::1")) {
		t.Fatal("expected 2606:4700::1 in AllowedIPv6")
	}
	if got.AllowedIPv4.Len() != 1 || !got.AllowedIPv4.Contains(net.ParseIP("1.2.3.4")) {
		t.Fatalf("AllowedIPv4 expected single dual-stack 1.2.3.4, got len=%d contains=%v",
			got.AllowedIPv4.Len(), got.AllowedIPv4.Contains(net.ParseIP("1.2.3.4")))
	}
	if len(got.UnresolvedDomains) != 0 {
		t.Fatalf("UnresolvedDomains: got %v want empty", got.UnresolvedDomains)
	}
	// v6-only: ip4 returns nil so retried up to maxAttempts; ip6 succeeds first try.
	if loadCallCount(&calls, "ip4|v6-only.example.com") != 2 {
		t.Fatalf("ip4|v6-only retries: got %d want 2", loadCallCount(&calls, "ip4|v6-only.example.com"))
	}
	if loadCallCount(&calls, "ip6|v6-only.example.com") != 1 {
		t.Fatalf("ip6|v6-only: got %d want 1", loadCallCount(&calls, "ip6|v6-only.example.com"))
	}
}

func TestCompileDomainAllowlist_AAAAErrorFallsBackToIPv4(t *testing.T) {
	ctx := context.Background()
	resolver := func(_ context.Context, network, host string) ([]net.IP, error) {
		if host != "ipv4-only.example.com" {
			return nil, errors.New("unexpected host")
		}
		if network == "ip4" {
			return []net.IP{net.ParseIP("198.51.100.1")}, nil
		}
		return nil, errors.New("NXDOMAIN")
	}

	got := CompileDomainAllowlist(ctx, []string{"ipv4-only.example.com"}, resolver, 2)

	if got.AllowedIPv4.Len() != 1 || !got.AllowedIPv4.Contains(net.ParseIP("198.51.100.1")) {
		t.Fatalf("AllowedIPv4 missing 198.51.100.1: len=%d", got.AllowedIPv4.Len())
	}
	if got.AllowedIPv6.Len() != 0 {
		t.Fatalf("AllowedIPv6.Len()=%d want 0 (AAAA NXDOMAIN)", got.AllowedIPv6.Len())
	}
	if len(got.UnresolvedDomains) != 0 {
		t.Fatalf("UnresolvedDomains: got %v want empty (A succeeded)", got.UnresolvedDomains)
	}
}

func TestIPv6SetContainsRejectsIPv4(t *testing.T) {
	var s IPv6Set
	s.Add(net.ParseIP("2001:db8::1"))
	s.Add(net.ParseIP("1.2.3.4")) // IPv4 input ignored
	if s.Len() != 1 {
		t.Fatalf("IPv6Set.Len()=%d want 1 (IPv4 input must not insert)", s.Len())
	}
	if !s.Contains(net.ParseIP("2001:db8::1")) {
		t.Fatal("expected 2001:db8::1 to be present")
	}
	if s.Contains(net.ParseIP("1.2.3.4")) {
		t.Fatal("IPv6Set should not match an IPv4 lookup")
	}
	if s.Contains(nil) {
		t.Fatal("nil IP should not match")
	}
}

func TestCompileDomainAllowlist_HighCardinalityIPv4Warns(t *testing.T) {
	ctx := context.Background()
	var buf bytes.Buffer
	h := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})
	old := slog.Default()
	slog.SetDefault(slog.New(h))
	defer slog.SetDefault(old)

	ips := make([]net.IP, 0, 12)
	for i := 0; i < 12; i++ {
		ips = append(ips, net.IPv4(10, 0, 0, byte(i+1)))
	}
	resolver := func(_ context.Context, _, _ string) ([]net.IP, error) {
		return ips, nil
	}
	got := CompileDomainAllowlist(ctx, []string{"cdn-heavy.example.com"}, resolver, 2)
	if got.AllowedIPv4.Len() != 12 {
		t.Fatalf("AllowedIPv4.Len()=%d want 12", got.AllowedIPv4.Len())
	}
	b := buf.Bytes()
	if !bytes.Contains(b, []byte(`"unique_ipv4":12`)) || !bytes.Contains(b, []byte(`cdn-heavy.example.com`)) {
		t.Fatalf("expected high-cardinality warn log, got %q", string(b))
	}
}
