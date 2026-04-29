// Package integrity implements the v3.0 capability gate: required-types
// check, canary-rules matcher, balanced score, coverage matrix, and the
// composing evaluator that emits a Verdict + closed-enum Reasons. See
// docs/superpowers/specs/2026-04-28-coldstep-report-go-port-design.md §3.
package integrity

const (
	VerdictPass = "pass"
	VerdictWarn = "warn"
	VerdictFail = "fail"

	DefaultFailThreshold = 60
	DefaultPassThreshold = 80
)

// DefaultWeights matches Python build_report_model.py:
//
//	{"integrity": 0.5, "coverage": 0.4, "correlation": 0.1}
func DefaultWeights() map[string]float64 {
	return map[string]float64{
		"integrity":   0.5,
		"coverage":    0.4,
		"correlation": 0.1,
	}
}
