"""Confidence-tier classifier for OTX malicious verdicts.

Pure transformation over the OTX `general`-section response. Never raises.
Only computes confidence when verdict == "malicious"; callers pass
confidence=None for clean/unidentified rows.

Design: docs/superpowers/specs/2026-04-19-otx-verdict-quality-design.md
Brain:  knowledge/wiki/otx-threat-intel-api.md (Verdict-quality refactor)
"""
from __future__ import annotations

import datetime as dt
import re
from typing import Optional

# HARD drops: troll / test / placeholder pulses. Removed from the count
# entirely by _filtered_pulses(). See knowledge/raw/2026-04-19-graylog-otx-issue-84.md
# for the "dont subscribe" story.
PULSE_HARD_DROP_RE = re.compile(
    r"\b(?:dont[- ]?subscribe|test[- ]pulse|wallpaper)\b",
    re.IGNORECASE,
)

# SOFT / generic-list: real pulses but bulk feeds / honeypot mass-exports.
# Kept in the count; if ALL surviving pulses match, tier collapses to "low".
GENERIC_LIST_NAME_RE = re.compile(
    r"\b(?:t-?pot|honeypot|mass[- ]?ip|"
    r"ioc[- ]?(?:list|export|feed|dump|sweep)|"
    r"port[- ]?scan(?:ners?)?|"
    r"abuseipdb|"
    r"(?:malicious|abuse)[- ]?ip[- ]?(?:list|dump)?)\b",
    re.IGNORECASE,
)

# PR2 (schema v2.2) populates this. Kept as an empty dict in PR1 so tier()
# can reference it without ImportError; PR2 replaces the value in-place.
KNOWN_CLOUD_ASNS: dict[int, str] = {}

# PR3 (schema v2.3) compiles this. Empty regex pattern in PR1 (matches
# nothing) so tier() can reference it without ImportError.
CLOUD_DNS_RE = re.compile(r"$^")  # matches nothing


def _filtered_pulses(otx_general: Optional[dict]) -> list[dict]:
    """Apply PULSE_HARD_DROP_RE + is_subscribing filter with graceful degrade.

    Never raises on malformed input — defensively returns an empty list.
    """
    if not isinstance(otx_general, dict):
        return []
    pulses = ((otx_general.get("pulse_info") or {}).get("pulses") or [])
    # Pre-compute the graceful-degrade signal BEFORE filtering, over the
    # post-hard-drop population, so a single troll pulse with is_subscribing
    # True doesn't force the filter to stay on for a legit all-False payload.
    post_hard = [p for p in pulses
                 if isinstance(p, dict)
                 and not PULSE_HARD_DROP_RE.search(p.get("name", "") or "")]
    any_has_field = any("is_subscribing" in p for p in post_hard)
    all_unsubscribed = any_has_field and all(
        not p.get("is_subscribing") for p in post_hard
    )
    apply_sub_filter = any_has_field and not all_unsubscribed
    out: list[dict] = []
    for p in post_hard:
        if apply_sub_filter and not p.get("is_subscribing"):
            continue
        out.append(p)
    return out


def _demote(t: str) -> str:
    """high → medium → low → low (floor). Never raises."""
    return {"high": "medium", "medium": "low", "low": "low"}[t]
