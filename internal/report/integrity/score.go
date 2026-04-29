package integrity

import "math"

// BalancedScore ports Python balanced_score from build_report_model.py.
// It computes weighted arithmetic only; hard-fail and verdict derivation are
// handled by the caller.
func BalancedScore(integrityScore, coverageScore, correlationScore int, weights map[string]float64) int {
	w := DefaultWeights()
	for k, v := range weights {
		w[k] = v
	}
	raw :=
		w["integrity"]*float64(integrityScore) +
			w["coverage"]*float64(coverageScore) +
			w["correlation"]*float64(correlationScore)
	val := roundHalfEven(raw)
	if val < 0 {
		return 0
	}
	if val > 100 {
		return 100
	}
	return val
}

func roundHalfEven(x float64) int {
	floor := math.Floor(x)
	frac := x - floor
	if frac < 0.5 {
		return int(floor)
	}
	if frac > 0.5 {
		return int(floor) + 1
	}
	// exactly .5 => nearest even
	if int(floor)%2 == 0 {
		return int(floor)
	}
	return int(floor) + 1
}
