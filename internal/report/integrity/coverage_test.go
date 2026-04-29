package integrity

import (
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
	if section.Score >= 100 {
		t.Errorf("score=%d; want <100", section.Score)
	}
	if len(section.UnobservedPaths) == 0 {
		t.Error("expected unobserved paths")
	}
}
