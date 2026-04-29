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

func TestDiffWithBaselineIncludesNewGoneChangedAndIndicators(t *testing.T) {
	current := []Event{
		{"type": "tcp", "fqdn": "new.example", "dst": "1.1.1.1"},
		{"type": "tls", "fqdn": "changed.example", "dst": "3.3.3.3"},
		{"type": "tls", "fqdn": "changed.example", "dst": "3.3.3.3"},
	}
	baseline := []Event{
		{"type": "udp", "fqdn": "gone.example", "dst": "2.2.2.2"},
		{"type": "tls", "fqdn": "changed.example", "dst": "3.3.3.3"},
	}

	d := BuildDiff(current, baseline)
	if got, want := d.Status, "ok"; got != want {
		t.Fatalf("diff.status = %q; want %q", got, want)
	}
	if got, want := len(d.TrafficNew), 1; got != want {
		t.Fatalf("traffic_new count = %d; want %d", got, want)
	}
	if got, want := len(d.TrafficGone), 1; got != want {
		t.Fatalf("traffic_gone count = %d; want %d", got, want)
	}
	if got, want := len(d.TrafficChanged), 1; got != want {
		t.Fatalf("traffic_changed count = %d; want %d", got, want)
	}

	newByFP := map[string]DiffEntry{}
	for _, e := range d.TrafficNew {
		newByFP[e.Fingerprint] = e
	}
	goneByFP := map[string]DiffEntry{}
	for _, e := range d.TrafficGone {
		goneByFP[e.Fingerprint] = e
	}
	changedByFP := map[string]DiffChanged{}
	for _, e := range d.TrafficChanged {
		changedByFP[e.Fingerprint] = e
	}

	newEntry, ok := newByFP["tcp»new.example"]
	if !ok {
		t.Fatal("missing expected new fingerprint tcp»new.example")
	}
	if len(newEntry.Indicators) == 0 {
		t.Fatal("new entry indicators should be non-empty")
	}
	if !containsString(newEntry.Indicators, "1.1.1.1") {
		t.Errorf("new indicators %v missing dst indicator", newEntry.Indicators)
	}
	if !containsString(newEntry.Indicators, "new.example") {
		t.Errorf("new indicators %v missing host indicator", newEntry.Indicators)
	}

	goneEntry, ok := goneByFP["udp»gone.example"]
	if !ok {
		t.Fatal("missing expected gone fingerprint udp»gone.example")
	}
	if len(goneEntry.Indicators) == 0 {
		t.Fatal("gone entry indicators should be non-empty")
	}
	if !containsString(goneEntry.Indicators, "2.2.2.2") {
		t.Errorf("gone indicators %v missing dst indicator", goneEntry.Indicators)
	}
	if !containsString(goneEntry.Indicators, "gone.example") {
		t.Errorf("gone indicators %v missing host indicator", goneEntry.Indicators)
	}

	changedEntry, ok := changedByFP["tls»changed.example"]
	if !ok {
		t.Fatal("missing expected changed fingerprint tls»changed.example")
	}
	if len(changedEntry.Indicators) == 0 {
		t.Fatal("changed entry indicators should be non-empty")
	}
	if !containsString(changedEntry.Indicators, "3.3.3.3") {
		t.Errorf("changed indicators %v missing dst indicator", changedEntry.Indicators)
	}
	if !containsString(changedEntry.Indicators, "changed.example") {
		t.Errorf("changed indicators %v missing host indicator", changedEntry.Indicators)
	}
}

func TestEgressSankeyIncludesDstAndHostIndicators(t *testing.T) {
	events := []Event{
		{"type": "tls", "dst": "9.9.9.9", "sni": "edge.example", "policy": "allow"},
	}
	edges := BuildEgressSankey(events)
	if got, want := len(edges), 1; got != want {
		t.Fatalf("edge count = %d; want %d", got, want)
	}
	if !containsString(edges[0].Indicators, "9.9.9.9") {
		t.Errorf("indicators %v missing dst indicator", edges[0].Indicators)
	}
	if !containsString(edges[0].Indicators, "edge.example") {
		t.Errorf("indicators %v missing host indicator", edges[0].Indicators)
	}
}

func containsString(items []string, target string) bool {
	for _, item := range items {
		if item == target {
			return true
		}
	}
	return false
}
