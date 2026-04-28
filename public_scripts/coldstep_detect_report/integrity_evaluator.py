"""
Evaluates the integrity of the telemetry stream.
Checks for required event types and canary events.
"""

from typing import Any, Dict, List, Set


def evaluate_integrity(
    events: List[Dict[str, Any]],
    require_types: Set[str],
    canary_rules: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Checks if the telemetry stream contains all required types and satisfies canary rules.
    
    Args:
        events: List of event dictionaries from the telemetry stream.
        require_types: Set of event 'type' strings that MUST be present.
        canary_rules: List of rules, each with an 'id' and a 'predicate' dictionary.
                      A predicate is a set of key-value pairs that must match at least one event.
                      
    Returns:
        A dictionary with 'status' (pass/fail), 'score' (0 or 100), and 'reasons' (list of codes).
    """
    seen_types = {e.get("type") for e in events if isinstance(e, dict)}
    reasons = []

    # 1. Check required types
    missing_types = require_types - seen_types
    if missing_types:
        reasons.append("INTEGRITY_REQUIRED_TYPE_MISSING")

    # 2. Check canary rules
    for rule in canary_rules:
        pred = rule.get("predicate", {})
        if not pred:
            continue
            
        found = False
        for evt in events:
            if not isinstance(evt, dict):
                continue
            
            match = True
            for k, v in pred.items():
                if evt.get(k) != v:
                    match = False
                    break
            
            if match:
                found = True
                break
        
        if not found:
            reasons.append("INTEGRITY_CANARY_MISSING")
            break  # One missing canary is enough to fail integrity

    status = "fail" if reasons else "pass"
    score = 0 if reasons else 100
    
    return {
        "status": status,
        "score": score,
        "reasons": reasons,
        "details": {
            "missing_types": sorted(list(missing_types)),
            "seen_types": sorted(list(seen_types)),
        }
    }
