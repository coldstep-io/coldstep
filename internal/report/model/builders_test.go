package model

import (
	"path/filepath"
	"testing"
)

func loadFixture(t *testing.T) []Event {
	t.Helper()
	events, err := LoadEvents(filepath.Join("testdata", "sample.events.jsonl"))
	if err != nil {
		t.Fatalf("loadFixture: %v", err)
	}
	return events
}

func TestCapabilityMatrixContainsAllRequiredCapabilities(t *testing.T) {
	events := loadFixture(t)
	cells := BuildCapabilityMatrix(events)
	if got, want := len(cells), 8; got != want {
		t.Errorf("capability cells = %d; want %d", got, want)
	}
	byID := map[string]CapabilityCell{}
	for _, c := range cells {
		byID[c.ID] = c
	}
	if byID["exec"].Status != "pass" {
		t.Errorf("exec status = %q; want pass", byID["exec"].Status)
	}
	if byID["http"].Status != "fail" {
		t.Errorf("http status = %q; want fail (no http event in fixture)", byID["http"].Status)
	}
	if byID["bpf_audit"].EvidenceCount != 1 {
		t.Errorf("bpf_audit evidence_count = %d; want 1", byID["bpf_audit"].EvidenceCount)
	}
}

func TestEventsByTypeOrdersByCountDesc(t *testing.T) {
	events := loadFixture(t)
	rows := BuildEventsByType(events)
	if got, want := len(rows), 6; got != want {
		t.Errorf("events_by_type rows = %d; want %d (meta excluded)", got, want)
	}
	if rows[0].Type != "exec" {
		t.Errorf("first row = %q; want exec (count 2)", rows[0].Type)
	}
}

func TestTimelineGroupsByOneSecondBuckets(t *testing.T) {
	events := loadFixture(t)
	buckets := BuildTimeline(events)
	if len(buckets) == 0 {
		t.Error("expected at least one timeline bucket")
	}
	for _, b := range buckets {
		if b.Count <= 0 {
			t.Errorf("bucket count = %d; want > 0", b.Count)
		}
	}
}

func TestEgressSankeyCollectsHostPolicyEdges(t *testing.T) {
	events := loadFixture(t)
	edges := BuildEgressSankey(events)
	if len(edges) == 0 {
		t.Error("expected at least one sankey edge")
	}
	// Sanity: the tls event with sni=theclouddj.com should appear as a source.
	found := false
	for _, e := range edges {
		if e.Source == "theclouddj.com" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected sankey edge with source=theclouddj.com")
	}
}

func TestDiffWithoutBaselineReportsUnavailable(t *testing.T) {
	events := loadFixture(t)
	d := BuildDiff(events, nil)
	if d.Status != "unavailable" {
		t.Errorf("diff.status = %q; want unavailable", d.Status)
	}
	if d.Reason != "no_baseline_provided" {
		t.Errorf("diff.reason = %q; want no_baseline_provided", d.Reason)
	}
}
