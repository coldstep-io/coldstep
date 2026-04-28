"""
Evaluates the capability coverage matrix.
Maps observed event types against a required matrix.
"""

from typing import Any, Dict, List


def evaluate_coverage(
    events: List[Dict[str, Any]],
    matrix: Dict[str, List[str]],
) -> Dict[str, Any]:
    """
    Computes coverage score based on a matrix of required capabilities.
    
    Args:
        events: List of event dictionaries.
        matrix: Dictionary where 'syscalls' is a list of required event types.
        
    Returns:
        A dictionary with 'coverage_cells', 'unobserved_paths', and 'score'.
    """
    seen = {e.get("type") for e in events if isinstance(e, dict)}
    cells = matrix.get("syscalls", [])
    
    if not cells:
        return {
            "coverage_cells": [],
            "unobserved_paths": [],
            "score": 100,
        }
        
    unobserved = [c for c in cells if c not in seen]
    observed = [c for c in cells if c in seen]
    
    score = int(round((len(observed) / len(cells)) * 100))
    
    return {
        "coverage_cells": [{"cell": c, "observed": c in seen} for c in cells],
        "unobserved_paths": unobserved,
        "score": score,
    }
