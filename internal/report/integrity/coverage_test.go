package integrity

import (
	"reflect"
	"testing"

	"github.com/coldstep-io/coldstep/internal/report/model"
)

func TestEvaluateCoverageAllObserved(t *testing.T) {
	events := []model.Event{
		{"type": "meta"},
		{"type": "exec"},
		{"type": "tcp"},
		{"type": "udp"},
		{"type": "tls"},
		{"type": "http"},
		{"type": "proc_fork"},
		{"type": "fs_event"},
		{"type": "bpf_audit"},
	}
	section := EvaluateCoverage(events)
	if section.Score != 100 {
		t.Errorf("score=%d; want 100", section.Score)
	}
	if len(section.UnobservedPaths) != 0 {
		t.Errorf("unobserved=%v; want []", section.UnobservedPaths)
	}
}

func TestEvaluateCoverageMissingSome(t *testing.T) {
	events := []model.Event{
		{"type": "meta"},
		{"type": "exec"},
		{"type": "tcp"},
	}
	section := EvaluateCoverage(events)
	if section.Score != 33 {
		t.Errorf("score=%d; want 33", section.Score)
	}
	wantUnobserved := []string{"udp", "tls", "http", "proc_fork", "fs_event", "bpf_audit"}
	if !reflect.DeepEqual(section.UnobservedPaths, wantUnobserved) {
		t.Errorf("unobserved=%v; want %v", section.UnobservedPaths, wantUnobserved)
	}
}

func TestEvaluateCoverageRoundsNearest(t *testing.T) {
	events := []model.Event{
		{"type": "meta"},
		{"type": "exec"},
		{"type": "tcp"},
		{"type": "udp"},
		{"type": "tls"},
	}
	section := EvaluateCoverage(events)
	if section.Score != 56 {
		t.Errorf("score=%d; want 56", section.Score)
	}
}

func TestEvaluateCoverageZeroEvents(t *testing.T) {
	section := EvaluateCoverage(nil)
	if section.Score != 0 {
		t.Errorf("score=%d; want 0", section.Score)
	}
	if len(section.UnobservedPaths) != 9 {
		t.Errorf("len(unobserved)=%d; want 9", len(section.UnobservedPaths))
	}
}
