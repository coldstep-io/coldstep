package policy

import (
	"context"
	"net"
	"reflect"
	"sync/atomic"
	"testing"
)

// makeCompileResult constructs a CompileResult whose AllowedIPv4 set contains
// the given dotted-quad addresses. Used by Diff tests to drive both sides of
// the comparison without going through CompileDomainAllowlist.
func makeCompileResult(domains []string, ipv4s ...string) CompileResult {
	cr := CompileResult{
		Domains:     append([]string(nil), domains...),
		AllowedIPv4: IPv4Set{},
		AllowedIPv6: IPv6Set{},
	}
	for _, s := range ipv4s {
		cr.AllowedIPv4.Add(net.ParseIP(s))
	}
	return cr
}

func TestDiff_NoChange(t *testing.T) {
	original := makeCompileResult([]string{"example.com"}, "1.1.1.1", "2.2.2.2")
	updated := makeCompileResult([]string{"example.com"}, "1.1.1.1", "2.2.2.2")

	dr := Diff(original, updated)
	if len(dr.AddedIPs) != 0 {
		t.Fatalf("AddedIPs: got %v want empty", dr.AddedIPs)
	}
	if len(dr.RemovedIPs) != 0 {
		t.Fatalf("RemovedIPs: got %v want empty", dr.RemovedIPs)
	}
	if dr.CheckedAt.IsZero() {
		t.Fatal("CheckedAt should be set to time.Now()")
	}
}

func TestDiff_AddedOnly(t *testing.T) {
	original := makeCompileResult([]string{"example.com"}, "1.1.1.1")
	updated := makeCompileResult([]string{"example.com"}, "1.1.1.1", "2.2.2.2", "3.3.3.3")

	dr := Diff(original, updated)
	wantAdded := []string{"2.2.2.2", "3.3.3.3"}
	if !reflect.DeepEqual(dr.AddedIPs, wantAdded) {
		t.Fatalf("AddedIPs: got %v want %v", dr.AddedIPs, wantAdded)
	}
	if len(dr.RemovedIPs) != 0 {
		t.Fatalf("RemovedIPs: got %v want empty", dr.RemovedIPs)
	}
}

func TestDiff_RemovedOnly(t *testing.T) {
	original := makeCompileResult([]string{"example.com"}, "1.1.1.1", "2.2.2.2", "3.3.3.3")
	updated := makeCompileResult([]string{"example.com"}, "1.1.1.1")

	dr := Diff(original, updated)
	wantRemoved := []string{"2.2.2.2", "3.3.3.3"}
	if !reflect.DeepEqual(dr.RemovedIPs, wantRemoved) {
		t.Fatalf("RemovedIPs: got %v want %v", dr.RemovedIPs, wantRemoved)
	}
	if len(dr.AddedIPs) != 0 {
		t.Fatalf("AddedIPs: got %v want empty", dr.AddedIPs)
	}
}

func TestDiff_AddedAndRemoved(t *testing.T) {
	// CDN tenant flipped: 1.1.1.1 dropped, 9.9.9.9 + 10.10.10.10 added.
	original := makeCompileResult([]string{"cdn.example.com"}, "1.1.1.1", "2.2.2.2")
	updated := makeCompileResult([]string{"cdn.example.com"}, "2.2.2.2", "9.9.9.9", "10.10.10.10")

	dr := Diff(original, updated)
	wantAdded := []string{"10.10.10.10", "9.9.9.9"} // sorted lexicographically
	wantRemoved := []string{"1.1.1.1"}
	if !reflect.DeepEqual(dr.AddedIPs, wantAdded) {
		t.Fatalf("AddedIPs: got %v want %v", dr.AddedIPs, wantAdded)
	}
	if !reflect.DeepEqual(dr.RemovedIPs, wantRemoved) {
		t.Fatalf("RemovedIPs: got %v want %v", dr.RemovedIPs, wantRemoved)
	}
}

func TestDiff_OutputIsSorted(t *testing.T) {
	original := makeCompileResult([]string{"a"}, "1.1.1.1")
	// IPv4Set ForEach iteration order over a map is random — Diff must sort.
	updated := makeCompileResult([]string{"a"},
		"1.1.1.1", "8.8.8.8", "2.2.2.2", "5.5.5.5", "3.3.3.3")

	dr := Diff(original, updated)
	wantAdded := []string{"2.2.2.2", "3.3.3.3", "5.5.5.5", "8.8.8.8"}
	if !reflect.DeepEqual(dr.AddedIPs, wantAdded) {
		t.Fatalf("AddedIPs (sorted): got %v want %v", dr.AddedIPs, wantAdded)
	}
}

func TestReResolve_RunsCompileWithOriginalDomainsAndDetectsDrift(t *testing.T) {
	ctx := context.Background()

	// Stage 1: original compile sees "1.1.1.1" for example.com.
	// Stage 2: re-resolve sees "1.1.1.1" + "5.5.5.5" (CDN expansion).
	var call atomic.Int32
	resolver := func(_ context.Context, network, host string) ([]net.IP, error) {
		if host != "example.com" {
			t.Fatalf("unexpected host %q", host)
		}
		if network != "ip4" {
			return nil, nil
		}
		n := call.Add(1)
		if n == 1 {
			return []net.IP{net.ParseIP("1.1.1.1")}, nil
		}
		return []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("5.5.5.5")}, nil
	}

	original := CompileDomainAllowlist(ctx, []string{"example.com"}, resolver, 1)
	if !original.AllowedIPv4.Contains(net.ParseIP("1.1.1.1")) {
		t.Fatal("original missing 1.1.1.1")
	}

	updated := ReResolve(ctx, original, resolver, 1)
	if !updated.AllowedIPv4.Contains(net.ParseIP("5.5.5.5")) {
		t.Fatalf("re-resolve missing 5.5.5.5; got Len=%d", updated.AllowedIPv4.Len())
	}

	dr := Diff(original, updated)
	if !reflect.DeepEqual(dr.AddedIPs, []string{"5.5.5.5"}) {
		t.Fatalf("drift AddedIPs: got %v", dr.AddedIPs)
	}
	if len(dr.RemovedIPs) != 0 {
		t.Fatalf("drift RemovedIPs: got %v want empty", dr.RemovedIPs)
	}
}
