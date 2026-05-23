package model

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadEventsParsesSampleFixture(t *testing.T) {
	path := filepath.Join("testdata", "sample.events.jsonl")
	events, err := LoadEvents(path)
	if err != nil {
		t.Fatalf("LoadEvents: %v", err)
	}
	if got, want := len(events), 8; got != want {
		t.Fatalf("event count = %d; want %d (malformed line skipped)", got, want)
	}
	if events[0]["type"] != "meta" {
		t.Errorf("first event type = %v; want meta", events[0]["type"])
	}
}

func TestLoadEventsReturnsErrOnMissingFile(t *testing.T) {
	if _, err := LoadEvents("/nonexistent"); err == nil {
		t.Error("expected error on missing file")
	}
}

// Bug #10: a leading UTF-8 BOM (EF BB BF) on the first line must not
// cause the first event (typically meta) to be dropped via silent
// json.Unmarshal failure. Reproduce a Windows-edited JSONL with BOM and
// assert the meta event is parsed correctly.
func TestLoadEventsStripsLeadingUTF8BOM(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "bom.jsonl")
	body := "\xef\xbb\xbf" + `{"type":"meta","schema":"v1"}` + "\n" +
		`{"type":"tcp","dst":"10.0.0.1"}` + "\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	events, err := LoadEvents(path)
	if err != nil {
		t.Fatalf("LoadEvents: %v", err)
	}
	if got, want := len(events), 2; got != want {
		t.Fatalf("event count = %d; want %d (BOM must not drop the meta line)", got, want)
	}
	if events[0]["type"] != "meta" {
		t.Fatalf("first event type = %v; want meta (BOM must not corrupt parse)", events[0]["type"])
	}
	if events[0]["schema"] != "v1" {
		t.Fatalf("first event schema = %v; want v1", events[0]["schema"])
	}
}

func TestLoadEventsRejectsTooManyParsedEvents(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "e.jsonl")
	var b strings.Builder
	for i := range 4 {
		fmt.Fprintf(&b, `{"type":"tcp","dst":"10.0.0.%d"}`+"\n", i)
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := loadEvents(path, loadEventsLimits{maxFileBytes: 1 << 20, maxScanLines: 100, maxParsed: 2})
	if err == nil || !strings.Contains(err.Error(), "max parsed events") {
		t.Fatalf("want max parsed events error, got %v", err)
	}
}

func TestLoadEventsRejectsOversizedFile(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "big.jsonl")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", 200)), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := loadEvents(path, loadEventsLimits{maxFileBytes: 100, maxScanLines: 10_000, maxParsed: 10_000})
	if err == nil || !strings.Contains(err.Error(), "max size") {
		t.Fatalf("want max size error, got %v", err)
	}
}

func TestLoadEventsRejectsTooManyScanLines(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "e.jsonl")
	var b strings.Builder
	for range 10 {
		b.WriteString("not-json\n")
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := loadEvents(path, loadEventsLimits{maxFileBytes: 1 << 20, maxScanLines: 5, maxParsed: 100})
	if err == nil || !strings.Contains(err.Error(), "max scan line count") {
		t.Fatalf("want max scan line count error, got %v", err)
	}
}

func TestEventAsString(t *testing.T) {
	ev := Event{
		"name": "  alice  ",
		"pid":  1234,
	}

	if got, want := ev.AsString("name"), "alice"; got != want {
		t.Errorf("AsString(name) = %q; want %q", got, want)
	}
	if got := ev.AsString("missing"); got != "" {
		t.Errorf("AsString(missing) = %q; want empty", got)
	}
	if got := ev.AsString("pid"); got != "" {
		t.Errorf("AsString(pid) = %q; want empty", got)
	}
}
