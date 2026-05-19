package model

import (
	"strings"
	"time"
)

// ObservationWindow returns the earliest and latest event timestamps in
// the stream and the duration between them. start is taken from the first
// "meta" event when available (the agent emits one meta record at startup,
// see internal/telemetry/meta_linux.go BuildMeta); otherwise from the
// earliest valid ts in the stream. end is the latest valid ts.
//
// Used by build-model to populate Report.ObservationHours so detect-mode
// learning windows can be gated for length (P1-2 / 4a).
func ObservationWindow(events []Event) (start, end time.Time, dur time.Duration) {
	var firstMeta time.Time
	for _, e := range events {
		ts := e.AsString("ts")
		if ts == "" {
			continue
		}
		t, err := parseEventTS(ts)
		if err != nil {
			continue
		}
		if e.AsString("type") == "meta" && firstMeta.IsZero() {
			firstMeta = t
		}
		if start.IsZero() || t.Before(start) {
			start = t
		}
		if t.After(end) {
			end = t
		}
	}
	if !firstMeta.IsZero() {
		start = firstMeta
	}
	if !start.IsZero() && !end.IsZero() && !end.Before(start) {
		dur = end.Sub(start)
	}
	return
}

// ObservationHours returns the wall-clock duration of the JSONL stream in
// hours (0 when no valid timestamps were present, or when the latest event
// preceded the start).
func ObservationHours(events []Event) float64 {
	_, _, dur := ObservationWindow(events)
	if dur <= 0 {
		return 0
	}
	return dur.Hours()
}

func parseEventTS(ts string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339Nano, strings.Replace(ts, "Z", "+00:00", 1)); err == nil {
		return t, nil
	}
	return time.Parse(time.RFC3339, ts)
}
