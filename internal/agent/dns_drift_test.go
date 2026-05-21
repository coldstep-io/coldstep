package agent

import (
	"context"
	"errors"
	"net"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coldstep-io/coldstep/internal/policy"
)

// buildOriginal compiles a CompileResult with a fixed IPv4 set, without going
// through CompileDomainAllowlist (so we don't have to mock the per-call resolver
// state machine for the initial compile).
func buildOriginal(domains []string, ipv4s ...string) policy.CompileResult {
	cr := policy.CompileResult{
		Domains:          append([]string(nil), domains...),
		AllowedIPv4:      policy.IPv4Set{},
		AllowedIPv6:      policy.IPv6Set{},
		CompileTimestamp: time.Now(),
	}
	for _, s := range ipv4s {
		cr.AllowedIPv4.Add(net.ParseIP(s))
	}
	return cr
}

func TestRunDNSDriftWatch_EmitsDriftWhenIPsChange(t *testing.T) {
	original := buildOriginal([]string{"cdn.example.com"}, "1.1.1.1")

	// Re-resolve will return 1.1.1.1 + 5.5.5.5 — addition of 5.5.5.5.
	resolver := func(_ context.Context, network, host string) ([]net.IP, error) {
		if network != "ip4" {
			return nil, nil
		}
		if host != "cdn.example.com" {
			t.Fatalf("unexpected host %q", host)
		}
		return []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("5.5.5.5")}, nil
	}

	driftCh := make(chan policy.DriftReport, 4)
	onDrift := func(dr policy.DriftReport) { driftCh <- dr }
	cleanCh := make(chan struct{}, 4)
	onClean := func() { cleanCh <- struct{}{} }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go runDNSDriftWatch(ctx, original, resolver, 1, 5*time.Millisecond, onDrift, onClean)

	select {
	case dr := <-driftCh:
		if !reflect.DeepEqual(dr.AddedIPs, []string{"5.5.5.5"}) {
			t.Fatalf("AddedIPs: got %v want [5.5.5.5]", dr.AddedIPs)
		}
		if len(dr.RemovedIPs) != 0 {
			t.Fatalf("RemovedIPs: got %v want empty", dr.RemovedIPs)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for onDrift")
	}
}

func TestRunDNSDriftWatch_NoDriftFiresOnClean(t *testing.T) {
	original := buildOriginal([]string{"stable.example.com"}, "1.1.1.1", "2.2.2.2")

	resolver := func(_ context.Context, network, host string) ([]net.IP, error) {
		if network != "ip4" {
			return nil, nil
		}
		return []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("2.2.2.2")}, nil
	}

	var driftCount, cleanCount atomic.Int32
	onDrift := func(_ policy.DriftReport) { driftCount.Add(1) }
	onClean := func() { cleanCount.Add(1) }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	doneCh := make(chan struct{})
	go func() {
		runDNSDriftWatch(ctx, original, resolver, 1, 5*time.Millisecond, onDrift, onClean)
		close(doneCh)
	}()

	// Let a couple of ticks run.
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-doneCh:
	case <-time.After(2 * time.Second):
		t.Fatal("runDNSDriftWatch did not return after cancel")
	}

	if driftCount.Load() != 0 {
		t.Fatalf("expected no drift; got %d drift callbacks", driftCount.Load())
	}
	if cleanCount.Load() == 0 {
		t.Fatal("expected at least one onClean callback")
	}
}

func TestRunDNSDriftWatch_RespectsContextCancellation(t *testing.T) {
	original := buildOriginal([]string{"x.example.com"}, "1.1.1.1")
	resolver := func(_ context.Context, _ string, _ string) ([]net.IP, error) {
		return nil, errors.New("should not be called when ctx already cancelled")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	doneCh := make(chan struct{})
	go func() {
		runDNSDriftWatch(ctx, original, resolver, 1, time.Hour, nil, nil)
		close(doneCh)
	}()

	select {
	case <-doneCh:
	case <-time.After(2 * time.Second):
		t.Fatal("runDNSDriftWatch did not return on pre-cancelled ctx")
	}
}

func TestRunDNSDriftWatch_NoDomainsIsNoop(t *testing.T) {
	original := buildOriginal(nil)
	called := false
	resolver := func(_ context.Context, _ string, _ string) ([]net.IP, error) {
		called = true
		return nil, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	doneCh := make(chan struct{})
	go func() {
		runDNSDriftWatch(ctx, original, resolver, 1, 5*time.Millisecond, nil, nil)
		close(doneCh)
	}()
	select {
	case <-doneCh:
	case <-time.After(time.Second):
		t.Fatal("expected immediate return with empty domain list")
	}
	if called {
		t.Fatal("resolver should not be called when domain list is empty")
	}
}

func TestRunDNSDriftWatch_DriftWithRemovedIPs(t *testing.T) {
	original := buildOriginal([]string{"shrink.example.com"}, "1.1.1.1", "2.2.2.2", "3.3.3.3")

	// Re-resolve only returns 1.1.1.1 — 2.2.2.2 and 3.3.3.3 dropped.
	resolver := func(_ context.Context, network, _ string) ([]net.IP, error) {
		if network != "ip4" {
			return nil, nil
		}
		return []net.IP{net.ParseIP("1.1.1.1")}, nil
	}

	driftCh := make(chan policy.DriftReport, 4)
	onDrift := func(dr policy.DriftReport) { driftCh <- dr }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go runDNSDriftWatch(ctx, original, resolver, 1, 5*time.Millisecond, onDrift, nil)

	select {
	case dr := <-driftCh:
		wantRemoved := []string{"2.2.2.2", "3.3.3.3"}
		if !reflect.DeepEqual(dr.RemovedIPs, wantRemoved) {
			t.Fatalf("RemovedIPs: got %v want %v", dr.RemovedIPs, wantRemoved)
		}
		if len(dr.AddedIPs) != 0 {
			t.Fatalf("AddedIPs: got %v want empty", dr.AddedIPs)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for onDrift")
	}
}

// TestRunDNSDriftWatch_TableDriven cycles through scenarios to validate the
// loop handles add-only, remove-only, and clean ticks with the expected
// callback counts.
func TestRunDNSDriftWatch_TableDriven(t *testing.T) {
	cases := []struct {
		name        string
		startIPs    []string
		resolveIPs  []net.IP
		wantDrift   bool
		wantAdded   []string
		wantRemoved []string
	}{
		{
			name:       "stable - no drift",
			startIPs:   []string{"1.1.1.1"},
			resolveIPs: []net.IP{net.ParseIP("1.1.1.1")},
			wantDrift:  false,
		},
		{
			name:        "single addition",
			startIPs:    []string{"1.1.1.1"},
			resolveIPs:  []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("4.4.4.4")},
			wantDrift:   true,
			wantAdded:   []string{"4.4.4.4"},
			wantRemoved: nil,
		},
		{
			name:        "complete CDN flip",
			startIPs:    []string{"1.1.1.1", "2.2.2.2"},
			resolveIPs:  []net.IP{net.ParseIP("9.9.9.9"), net.ParseIP("10.10.10.10")},
			wantDrift:   true,
			wantAdded:   []string{"10.10.10.10", "9.9.9.9"},
			wantRemoved: []string{"1.1.1.1", "2.2.2.2"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			original := buildOriginal([]string{"host"}, tc.startIPs...)
			resolveIPs := append([]net.IP(nil), tc.resolveIPs...)
			resolver := func(_ context.Context, network, _ string) ([]net.IP, error) {
				if network != "ip4" {
					return nil, nil
				}
				return resolveIPs, nil
			}

			driftCh := make(chan policy.DriftReport, 1)
			cleanCh := make(chan struct{}, 1)
			onDrift := func(dr policy.DriftReport) {
				select {
				case driftCh <- dr:
				default:
				}
			}
			onClean := func() {
				select {
				case cleanCh <- struct{}{}:
				default:
				}
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			go runDNSDriftWatch(ctx, original, resolver, 1, 5*time.Millisecond, onDrift, onClean)

			if tc.wantDrift {
				select {
				case dr := <-driftCh:
					if !reflect.DeepEqual(dr.AddedIPs, tc.wantAdded) {
						t.Fatalf("AddedIPs: got %v want %v", dr.AddedIPs, tc.wantAdded)
					}
					if len(tc.wantRemoved) == 0 {
						if len(dr.RemovedIPs) != 0 {
							t.Fatalf("RemovedIPs: got %v want empty", dr.RemovedIPs)
						}
					} else if !reflect.DeepEqual(dr.RemovedIPs, tc.wantRemoved) {
						t.Fatalf("RemovedIPs: got %v want %v", dr.RemovedIPs, tc.wantRemoved)
					}
				case <-time.After(2 * time.Second):
					t.Fatal("expected onDrift; timed out")
				}
				return
			}
			select {
			case <-cleanCh:
			case <-driftCh:
				t.Fatal("expected onClean; got onDrift")
			case <-time.After(2 * time.Second):
				t.Fatal("expected onClean; timed out")
			}
		})
	}
}
