package model

import (
	"math"
	"testing"
)

func TestObservationHoursUsesMetaAsStart(t *testing.T) {
	events := []Event{
		{"type": "meta", "ts": "2026-05-18T10:00:00Z"},
		{"type": "tcp", "ts": "2026-05-18T11:30:00Z", "dst": "1.1.1.1"},
		{"type": "tcp", "ts": "2026-05-18T14:00:00Z", "dst": "2.2.2.2"},
	}
	got := ObservationHours(events)
	if math.Abs(got-4.0) > 1e-6 {
		t.Fatalf("ObservationHours = %v; want 4.0", got)
	}
}

func TestObservationHoursFallsBackToEarliestEventWhenNoMeta(t *testing.T) {
	events := []Event{
		{"type": "tcp", "ts": "2026-05-18T10:00:00Z", "dst": "1.1.1.1"},
		{"type": "tcp", "ts": "2026-05-18T11:00:00Z", "dst": "2.2.2.2"},
	}
	got := ObservationHours(events)
	if math.Abs(got-1.0) > 1e-6 {
		t.Fatalf("ObservationHours = %v; want 1.0", got)
	}
}

func TestObservationHoursZeroWhenNoTimestamps(t *testing.T) {
	events := []Event{
		{"type": "tcp", "dst": "1.1.1.1"},
		{"type": "exec", "comm": "bash"},
	}
	got := ObservationHours(events)
	if got != 0 {
		t.Fatalf("ObservationHours = %v; want 0", got)
	}
}

func TestObservationHoursIgnoresMalformedTS(t *testing.T) {
	events := []Event{
		{"type": "meta", "ts": "not a timestamp"},
		{"type": "tcp", "ts": "2026-05-18T10:00:00Z", "dst": "1.1.1.1"},
		{"type": "tcp", "ts": "2026-05-18T12:00:00Z", "dst": "2.2.2.2"},
	}
	got := ObservationHours(events)
	if math.Abs(got-2.0) > 1e-6 {
		t.Fatalf("ObservationHours = %v; want 2.0", got)
	}
}
