package model

import (
	"path/filepath"
	"testing"
)

func TestLoadEventsParsesSampleFixture(t *testing.T) {
	path := filepath.Join("testdata", "sample.events.jsonl")
	events, err := LoadEvents(path)
	if err != nil {
		t.Fatalf("LoadEvents: %v", err)
	}
	if got, want := len(events), 8; got != want {
		t.Errorf("event count = %d; want %d (malformed line skipped)", got, want)
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
