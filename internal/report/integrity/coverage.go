package integrity

import (
	"math"

	"github.com/coldstep-io/coldstep/internal/report/model"
)

// evaluateCoverage parity target: build_report_model.py evaluate_coverage.
func EvaluateCoverage(events []model.Event) model.CoverageSection {
	required := []string{"meta", "exec", "tcp", "udp", "tls", "http", "proc_fork", "fs_event", "bpf_audit"}
	seen := map[string]struct{}{}
	for _, e := range events {
		t := e.AsString("type")
		if t != "" {
			seen[t] = struct{}{}
		}
	}
	cells := make([]model.CoverageCell, 0, len(required))
	unobserved := make([]string, 0)
	observed := 0
	for _, r := range required {
		_, ok := seen[r]
		cells = append(cells, model.CoverageCell{Cell: r, Observed: ok})
		if ok {
			observed++
		} else {
			unobserved = append(unobserved, r)
		}
	}
	score := 0
	if len(required) == 0 {
		score = 100
	} else {
		score = int(math.Round((100.0 * float64(observed)) / float64(len(required))))
	}
	return model.CoverageSection{
		Score:           score,
		CoverageCells:   cells,
		UnobservedPaths: unobserved,
	}
}
