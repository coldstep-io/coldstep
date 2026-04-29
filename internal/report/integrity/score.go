package integrity

import "math"

// BalancedScore ports Python balanced_score from build_report_model.py.
func BalancedScore(integrityScore, coverageScore, correlationScore int, weights map[string]float64) int {
	w := map[string]float64{
		"integrity":   0.5,
		"coverage":    0.4,
		"correlation": 0.1,
	}
	for k, v := range weights {
		w[k] = v
	}
	raw :=
		w["integrity"]*float64(integrityScore) +
			w["coverage"]*float64(coverageScore) +
			w["correlation"]*float64(correlationScore)
	val := int(math.Round(raw))
	if val < 0 {
		return 0
	}
	if val > 100 {
		return 100
	}
	return val
}
