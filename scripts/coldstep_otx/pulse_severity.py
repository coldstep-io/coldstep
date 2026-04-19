"""Pulse signal severity from filtered OTX pulse count (Coldstep-specific tiers)."""
from __future__ import annotations

# Lower rank = sort first when ordering by descending threat (Critical first).
_SEVERITY_RANK: dict[str, int] = {
    "Critical": 0,
    "High": 1,
    "Medium": 2,
    "Low": 3,
    "Informational": 4,
}


def severity_rank(label: str) -> int:
    return _SEVERITY_RANK.get(label, 99)


def pulse_signal_severity(*, verdict: str, filtered_pulse_count: int) -> str:
    if verdict != "malicious":
        return "Informational"
    n = max(0, int(filtered_pulse_count))
    if n <= 4:
        return "Low"
    if n <= 19:
        return "Medium"
    if n <= 49:
        return "High"
    return "Critical"
