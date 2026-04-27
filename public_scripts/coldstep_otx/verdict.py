"""Pure verdict classification from an OTX `general` response.

Mapping (locked, see knowledge/wiki/otx-threat-intel-api.md):
- validation[*] non-empty             -> "clean"        (whitelisted infra)
- pulse_info.count > 0 + no validation -> "malicious"   (community-reported)
- otherwise                           -> "unidentified" (no signal either way)

Defensive: any malformed response shape -> "unidentified" (never raises).
"""
from __future__ import annotations

from typing import Optional

EVIDENCE_LIMIT = 5
Verdict = str  # "malicious" | "clean" | "unidentified"


def _evidence_row(pulse: dict) -> dict:
    families = pulse.get("malware_families") or []
    attacks = pulse.get("attack_ids") or []
    return {
        "pulse_id": str(pulse.get("id", "")),
        "pulse_name": str(pulse.get("name", "")),
        "modified": str(pulse.get("modified", "")),
        "tags": [str(t) for t in (pulse.get("tags") or [])],
        "malware_families": [
            str((f.get("display_name") if isinstance(f, dict) else f) or "")
            for f in families if f
        ],
        "attack_ids": [
            str((a.get("id") if isinstance(a, dict) else a) or "")
            for a in attacks if a
        ],
        "tlp": str(pulse.get("tlp", "")),
    }


def classify(general: Optional[dict]) -> tuple[Verdict, list[dict]]:
    if not isinstance(general, dict):
        return ("unidentified", [])
    validation = general.get("validation") or []
    if validation:
        return ("clean", [])
    pulse_info = general.get("pulse_info") or {}
    pulses = pulse_info.get("pulses") or []
    count = pulse_info.get("count", len(pulses))
    if not pulses or count == 0:
        return ("unidentified", [])
    sorted_pulses = sorted(
        (p for p in pulses if isinstance(p, dict)),
        key=lambda p: str(p.get("modified", "")),
        reverse=True,
    )
    evidence = [_evidence_row(p) for p in sorted_pulses[:EVIDENCE_LIMIT]]
    return ("malicious", evidence)
