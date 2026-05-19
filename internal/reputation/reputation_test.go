package reputation_test

import (
	"context"
	"errors"
	"sort"
	"testing"
	"time"

	"github.com/coldstep-io/coldstep/internal/reputation"
	"github.com/coldstep-io/coldstep/internal/reputation/loader"
)

// fakeEnricher is a controllable test enricher.
type fakeEnricher struct {
	name   string
	delay  time.Duration
	result *reputation.Result
	err    error
}

func (f *fakeEnricher) Name() string { return f.name }

func (f *fakeEnricher) Enrich(ctx context.Context, ip string) (*reputation.Result, error) {
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if f.err != nil {
		return nil, f.err
	}
	if f.result == nil {
		return nil, nil
	}
	clone := *f.result
	clone.IP = ip
	clone.Enricher = f.name
	return &clone, nil
}

// hangEnricher never returns until ctx fires. Used to verify EnrichAll
// does not block on a stuck backend.
type hangEnricher struct{ name string }

func (h *hangEnricher) Name() string { return h.name }
func (h *hangEnricher) Enrich(ctx context.Context, _ string) (*reputation.Result, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestNoOpEnricher_SatisfiesInterface(t *testing.T) {
	var _ reputation.Enricher = reputation.NoOpEnricher{}
	n := reputation.NewNoOp("otx")
	if got := n.Name(); got != "otx" {
		t.Fatalf("Name() = %q, want otx", got)
	}
	res, err := n.Enrich(context.Background(), "1.2.3.4")
	if res != nil || err != nil {
		t.Fatalf("NoOp Enrich = (%v, %v), want (nil, nil)", res, err)
	}
}

func TestRegister_Registered_RoundTrip(t *testing.T) {
	reputation.Reset()
	t.Cleanup(reputation.Reset)

	a := &fakeEnricher{name: "alpha"}
	b := &fakeEnricher{name: "beta"}
	reputation.Register(a)
	reputation.Register(b)
	reputation.Register(nil) // ignored

	got := reputation.Registered()
	if len(got) != 2 {
		t.Fatalf("Registered() len = %d, want 2", len(got))
	}
	if got[0].Name() != "alpha" || got[1].Name() != "beta" {
		t.Fatalf("Registered() = [%s, %s], want [alpha, beta]", got[0].Name(), got[1].Name())
	}

	// Re-registering the same name should replace, not duplicate.
	a2 := &fakeEnricher{name: "alpha", err: errors.New("replaced")}
	reputation.Register(a2)
	got = reputation.Registered()
	if len(got) != 2 {
		t.Fatalf("after replace, len = %d, want 2", len(got))
	}
	if got[0] != a2 {
		t.Fatalf("alpha slot was not replaced")
	}
}

func TestRegistered_ReturnsCopy(t *testing.T) {
	reputation.Reset()
	t.Cleanup(reputation.Reset)

	reputation.Register(&fakeEnricher{name: "alpha"})
	snap := reputation.Registered()
	snap[0] = &fakeEnricher{name: "tampered"}

	again := reputation.Registered()
	if again[0].Name() != "alpha" {
		t.Fatalf("internal slice was mutated through the returned copy")
	}
}

func TestEnrichAll_CallsAllEnrichersAndCombines(t *testing.T) {
	reputation.Reset()
	t.Cleanup(reputation.Reset)

	reputation.Register(&fakeEnricher{
		name:   "alpha",
		result: &reputation.Result{Score: 3.0, Tags: []string{"scanner"}},
	})
	reputation.Register(&fakeEnricher{
		name:   "beta",
		result: &reputation.Result{Score: 7.5, Tags: []string{"malware"}},
	})

	results, err := reputation.EnrichAll(context.Background(), "1.2.3.4")
	if err != nil {
		t.Fatalf("EnrichAll error: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("results len = %d, want 2", len(results))
	}
	// Sort-by-name ordering is part of the contract.
	if results[0].Enricher != "alpha" || results[1].Enricher != "beta" {
		t.Fatalf("results not sorted by enricher name: %v / %v", results[0].Enricher, results[1].Enricher)
	}
	if results[0].IP != "1.2.3.4" {
		t.Fatalf("IP propagated incorrectly: %q", results[0].IP)
	}
}

func TestEnrichAll_NilResultsAreSkipped(t *testing.T) {
	reputation.Reset()
	t.Cleanup(reputation.Reset)

	reputation.Register(reputation.NewNoOp("disabled"))
	reputation.Register(&fakeEnricher{
		name:   "active",
		result: &reputation.Result{Score: 1.0},
	})

	results, err := reputation.EnrichAll(context.Background(), "1.2.3.4")
	if err != nil {
		t.Fatalf("EnrichAll error: %v", err)
	}
	if len(results) != 1 || results[0].Enricher != "active" {
		t.Fatalf("expected only 'active' result, got %#v", results)
	}
}

func TestEnrichAll_EmptyRegistry(t *testing.T) {
	reputation.Reset()
	t.Cleanup(reputation.Reset)

	results, err := reputation.EnrichAll(context.Background(), "1.2.3.4")
	if err != nil || results != nil {
		t.Fatalf("empty registry: got (%v, %v), want (nil, nil)", results, err)
	}
}

func TestEnrichAll_HungEnricherDoesNotBlockOthers(t *testing.T) {
	reputation.Reset()
	t.Cleanup(reputation.Reset)

	reputation.Register(&hangEnricher{name: "slow"})
	reputation.Register(&fakeEnricher{
		name:   "fast",
		result: &reputation.Result{Score: 4.0},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	start := time.Now()
	results, err := reputation.EnrichAll(ctx, "9.9.9.9")
	elapsed := time.Since(start)

	// We expect the fast enricher's result to be returned, and we expect
	// EnrichAll to return well before any "long" timeout because once
	// ctx fires it stops waiting on the hung enricher.
	if elapsed > 2*time.Second {
		t.Fatalf("EnrichAll waited too long (%v) — should bail out on ctx deadline", elapsed)
	}
	// err should reflect the context deadline.
	if err == nil {
		t.Fatalf("expected ctx error from EnrichAll, got nil")
	}
	foundFast := false
	for _, r := range results {
		if r.Enricher == "fast" {
			foundFast = true
		}
	}
	if !foundFast {
		t.Fatalf("fast enricher's result missing despite hung neighbour: %#v", results)
	}
}

func TestEnrichAll_PartialErrorsReturned(t *testing.T) {
	reputation.Reset()
	t.Cleanup(reputation.Reset)

	reputation.Register(&fakeEnricher{name: "good", result: &reputation.Result{Score: 2}})
	reputation.Register(&fakeEnricher{name: "bad", err: errors.New("backend exploded")})

	results, err := reputation.EnrichAll(context.Background(), "1.1.1.1")
	if err == nil || !contains(err.Error(), "backend exploded") {
		t.Fatalf("expected backend error to be surfaced, got %v", err)
	}
	if len(results) != 1 || results[0].Enricher != "good" {
		t.Fatalf("expected 'good' result alongside error, got %#v", results)
	}
}

func TestLoadFromEnv_Table(t *testing.T) {
	cases := []struct {
		name      string
		env       map[string]string
		wantNames []string
		wantNoOp  map[string]bool // backend -> is no-op
	}{
		{
			name:      "all empty",
			env:       map[string]string{},
			wantNames: []string{"otx", "virustotal", "passivedns"},
			wantNoOp:  map[string]bool{"otx": true, "virustotal": true, "passivedns": true},
		},
		{
			name:      "otx only",
			env:       map[string]string{loader.EnvOTXAPIKey: "abc"},
			wantNames: []string{"otx", "virustotal", "passivedns"},
			wantNoOp:  map[string]bool{"otx": false, "virustotal": true, "passivedns": true},
		},
		{
			name: "all three",
			env: map[string]string{
				loader.EnvOTXAPIKey:        "abc",
				loader.EnvVirusTotalAPIKey: "def",
				loader.EnvPassiveDNSServer: "https://pdns.example/",
			},
			wantNames: []string{"otx", "virustotal", "passivedns"},
			wantNoOp:  map[string]bool{"otx": false, "virustotal": false, "passivedns": false},
		},
		{
			name:      "whitespace-only treated as empty",
			env:       map[string]string{loader.EnvOTXAPIKey: "   "},
			wantNames: []string{"otx", "virustotal", "passivedns"},
			wantNoOp:  map[string]bool{"otx": true, "virustotal": true, "passivedns": true},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, k := range []string{loader.EnvOTXAPIKey, loader.EnvVirusTotalAPIKey, loader.EnvPassiveDNSServer} {
				t.Setenv(k, "")
			}
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			got := loader.LoadFromEnv()
			names := make([]string, len(got))
			for i, e := range got {
				names[i] = e.Name()
			}
			if !equalStringSlice(names, tc.wantNames) {
				t.Fatalf("names = %v, want %v", names, tc.wantNames)
			}
			for _, e := range got {
				_, isNoOp := e.(reputation.NoOpEnricher)
				if isNoOp != tc.wantNoOp[e.Name()] {
					t.Fatalf("%s: NoOp=%v, want %v", e.Name(), isNoOp, tc.wantNoOp[e.Name()])
				}
			}
		})
	}
}

func TestEnrichAll_Deterministic(t *testing.T) {
	reputation.Reset()
	t.Cleanup(reputation.Reset)

	for _, name := range []string{"zeta", "alpha", "mu"} {
		reputation.Register(&fakeEnricher{name: name, result: &reputation.Result{Score: 1}})
	}
	results, err := reputation.EnrichAll(context.Background(), "8.8.8.8")
	if err != nil {
		t.Fatalf("EnrichAll: %v", err)
	}
	got := make([]string, len(results))
	for i, r := range results {
		got[i] = r.Enricher
	}
	want := []string{"alpha", "mu", "zeta"}
	sort.Strings(want)
	if !equalStringSlice(got, want) {
		t.Fatalf("not sorted by enricher name: got %v, want %v", got, want)
	}
}

func equalStringSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && indexOf(s, substr) >= 0
}

func indexOf(s, substr string) int {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
