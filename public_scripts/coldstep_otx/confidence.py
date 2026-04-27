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
CLOUD_DNS_RE = re.compile(r"(?!)")  # matches nothing (PR3 replaces with real cloud-PTR patterns)


def _filtered_pulses_with_audit(
    otx_general: Optional[dict],
) -> tuple[list[dict], list[dict]]:
    """Apply PULSE_HARD_DROP_RE + is_subscribing filter; return kept + drop audit.

    Each drop is ``{pulse_id, name, filtered_by}`` where ``filtered_by`` is
    ``name_blocklist`` (hard-drop regex) or ``is_subscribing=false``.
    Non-dict pulse entries are skipped with no audit row (same as before).
    Never raises on malformed input.
    """
    if not isinstance(otx_general, dict):
        return [], []
    pulses = ((otx_general.get("pulse_info") or {}).get("pulses") or [])
    dropped: list[dict] = []
    post_hard: list[dict] = []
    for p in pulses:
        if not isinstance(p, dict):
            continue
        if PULSE_HARD_DROP_RE.search(p.get("name", "") or ""):
            dropped.append({
                "pulse_id": str(p.get("id", "")),
                "name": p.get("name", ""),
                "filtered_by": "name_blocklist",
            })
        else:
            post_hard.append(p)
    any_has_field = any("is_subscribing" in p for p in post_hard)
    all_unsubscribed = any_has_field and all(
        not p.get("is_subscribing") for p in post_hard
    )
    apply_sub_filter = any_has_field and not all_unsubscribed
    kept: list[dict] = []
    for p in post_hard:
        if apply_sub_filter and not p.get("is_subscribing"):
            dropped.append({
                "pulse_id": str(p.get("id", "")),
                "name": p.get("name", ""),
                "filtered_by": "is_subscribing=false",
            })
            continue
        kept.append(p)
    return kept, dropped


def _filtered_pulses(otx_general: Optional[dict]) -> list[dict]:
    """Apply PULSE_HARD_DROP_RE + is_subscribing filter with graceful degrade.

    Never raises on malformed input — defensively returns an empty list.
    """
    return _filtered_pulses_with_audit(otx_general)[0]


_Z = dt.timezone.utc
STALE_PULSE_DAYS = 365


def _parse_iso(s: str) -> Optional[dt.datetime]:
    """Parse OTX pulse `modified` timestamps; assume UTC if no tz."""
    if not s:
        return None
    try:
        clean = str(s).strip().rstrip("Z")
        if "." in clean:
            head, frac = clean.split(".", 1)
            clean = head + "." + (frac + "000000")[:6]
            parsed = dt.datetime.fromisoformat(clean)
        else:
            parsed = dt.datetime.fromisoformat(clean)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=_Z)
        return parsed
    except (ValueError, TypeError):
        return None


def _newest_modified(pulses: list[dict]) -> Optional[dt.datetime]:
    dates = [_parse_iso(str(p.get("modified", "") or "")) for p in pulses]
    dates = [d for d in dates if d is not None]
    return max(dates) if dates else None


def tier(
    otx_general: Optional[dict],
    *,
    asn: Optional[dict] = None,
    hostname: Optional[str] = None,
    now: Optional[dt.datetime] = None,
) -> tuple[str, list[str]]:
    """Compute confidence tier + stacked demotion reasons. Never raises."""
    reasons: list[str] = []
    pulses = _filtered_pulses(otx_general)
    conf = "high"

    # PR1 rules: OTX-internal signals only
    if len(pulses) < 2:
        conf = _demote(conf)
        reasons.append(f"single pulse hit (count={len(pulses)})")
    if pulses and (
        not any(p.get("malware_families") for p in pulses)
        and not any(p.get("attack_ids") for p in pulses)
    ):
        conf = _demote(conf)
        reasons.append("no malware_families or attack_ids on any pulse")

    newest = _newest_modified(pulses)
    if newest is not None:
        now_dt = now or dt.datetime.now(_Z)
        if newest.tzinfo is None:
            newest = newest.replace(tzinfo=_Z)
        age_days = (now_dt - newest).days
        if age_days > STALE_PULSE_DAYS:
            conf = _demote(conf)
            reasons.append(f"newest pulse stale ({age_days}d)")

    if pulses and all(
        GENERIC_LIST_NAME_RE.search(p.get("name", "") or "") for p in pulses
    ):
        conf = "low"
        reasons.append(
            "all pulses are generic-list exports (T-Pot/feed/dump)",
        )

    # PR2 / PR3 hooks (PLACEHOLDER no-ops until populated)
    asn_id = asn.get("asn") if isinstance(asn, dict) else None
    if asn_id is not None and asn_id in KNOWN_CLOUD_ASNS:
        conf = _demote(conf)
        label = KNOWN_CLOUD_ASNS.get(asn_id, "?")
        reasons.append(f"shared cloud infra ({label}, AS{asn_id})")
    if hostname and CLOUD_DNS_RE.search(hostname.lower()):
        conf = _demote(conf)
        reasons.append(f"hostname matches CDN pattern ({hostname})")

    return conf, reasons


def _demote(t: str) -> str:
    """high → medium → low → low (floor). Never raises."""
    return {"high": "medium", "medium": "low", "low": "low"}[t]
