package integrity

import "testing"

func TestBalancedScoreUsesWeightsAndRoundsLikePython(t *testing.T) {
	weights := map[string]float64{"integrity": 0.5, "coverage": 0.4, "correlation": 0.1}
	got := BalancedScore(80, 70, 50, weights)
	// 0.5*80 + 0.4*70 + 0.1*50 = 40 + 28 + 5 = 73
	if got != 73 {
		t.Errorf("score=%d; want 73", got)
	}
}

func TestBalancedScoreDefaultsMissingWeightsToPythonDefaults(t *testing.T) {
	weights := map[string]float64{"integrity": 1.0}
	got := BalancedScore(100, 50, 0, weights)
	// missing keys should default to 0.4 and 0.1 -> 100*1 + 50*0.4 + 0*0.1 = 120, clamp 100
	if got != 100 {
		t.Errorf("score=%d; want 100 (clamped)", got)
	}
}

func TestBalancedScoreClampsLowerBound(t *testing.T) {
	weights := map[string]float64{"integrity": -2, "coverage": 0, "correlation": 0}
	got := BalancedScore(10, 10, 10, weights)
	if got != 0 {
		t.Errorf("score=%d; want 0", got)
	}
}

func TestBalancedScoreBankersRoundingHalfEven(t *testing.T) {
	weights := map[string]float64{"integrity": 0.5, "coverage": 0.5, "correlation": 0}
	got := BalancedScore(100, 5, 0, weights)
	// 0.5*100 + 0.5*5 + 0*0 = 52.5 -> half-to-even => 52
	if got != 52 {
		t.Errorf("score=%d; want 52", got)
	}
}

func TestBalancedScoreNilWeightsUsesDefaults(t *testing.T) {
	got := BalancedScore(80, 70, 50, nil)
	// default weights: 0.5*80 + 0.4*70 + 0.1*50 = 73
	if got != 73 {
		t.Errorf("score=%d; want 73", got)
	}
}
