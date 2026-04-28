"""
Aggregates multiple capability scores into a single balanced score and verdict.
"""

from typing import Any, Dict, List


def compute_balanced_score(
    integrity_score: int,
    coverage_score: int,
    correlation_score: int,
    weights: Dict[str, float],
    fail_threshold: int,
    pass_threshold: int,
    hard_fail_reasons: List[str],
) -> Dict[str, Any]:
    """
    Computes a weighted score and determines a verdict (pass, warn, fail).
    
    Args:
        integrity_score: 0-100 score from the integrity evaluator.
        coverage_score: 0-100 score from the coverage matrix evaluator.
        correlation_score: 0-100 score from correlation (placeholder for now).
        weights: Dictionary of weights for each component (should sum to 1.0).
        fail_threshold: Scores below this result in 'fail'.
        pass_threshold: Scores above this result in 'pass'; middle is 'warn'.
        hard_fail_reasons: If non-empty, score is 0 and verdict is 'fail'.
        
    Returns:
        A dictionary with 'score', 'verdict', and 'reasons'.
    """
    if hard_fail_reasons:
        return {
            "score": 0,
            "verdict": "fail",
            "reasons": hard_fail_reasons,
        }
        
    score = int(round(
        integrity_score * weights.get("integrity", 0.0) +
        coverage_score * weights.get("coverage", 0.0) +
        correlation_score * weights.get("correlation", 0.0)
    ))
    
    if score < fail_threshold:
        verdict = "fail"
    elif score < pass_threshold:
        verdict = "warn"
    else:
        verdict = "pass"
        
    return {
        "score": score,
        "verdict": verdict,
        "reasons": [],
    }
