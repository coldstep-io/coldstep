package integrity

import (
	"strings"
	"testing"

	"github.com/coldstep-io/coldstep/internal/report/model"
)

func TestRequireMinObservationHoursDisabledWhenThresholdZero(t *testing.T) {
	events := []model.Event{
		{"type": "meta", "ts": "2026-05-18T10:00:00Z"},
		{"type": "tcp", "ts": "2026-05-18T10:00:01Z"},
	}
	if err := RequireMinObservationHours(events, 0); err != nil {
		t.Fatalf("err = %v; want nil when min <= 0", err)
	}
}

func TestRequireMinObservationHoursPassesWhenWindowMeetsThreshold(t *testing.T) {
	events := []model.Event{
		{"type": "meta", "ts": "2026-05-18T10:00:00Z"},
		{"type": "tcp", "ts": "2026-05-18T13:00:00Z"},
	}
	if err := RequireMinObservationHours(events, 2.0); err != nil {
		t.Fatalf("err = %v; want nil (3h >= 2h)", err)
	}
}

func TestRequireMinObservationHoursFailsWhenWindowTooShort(t *testing.T) {
	events := []model.Event{
		{"type": "meta", "ts": "2026-05-18T10:00:00Z"},
		{"type": "tcp", "ts": "2026-05-18T10:30:00Z"},
	}
	err := RequireMinObservationHours(events, 24)
	if err == nil {
		t.Fatal("err = nil; want short-window error")
	}
	if !strings.Contains(err.Error(), "0.50") {
		t.Errorf("err = %q; expected current hours in message", err)
	}
}

func TestRequireMinObservationHoursFailsWhenNoTimestamps(t *testing.T) {
	events := []model.Event{
		{"type": "tcp", "dst": "1.1.1.1"},
	}
	if err := RequireMinObservationHours(events, 1); err == nil {
		t.Fatal("err = nil; want error (0h window)")
	}
}
