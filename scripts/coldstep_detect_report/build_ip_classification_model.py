"""Build a minimal IP/FQDN/rDNS classification model for detect-dev reports."""
from __future__ import annotations

import datetime as dt
import ipaddress
import json
import os
import re
import sys
import tempfile
from pathlib import Path

SCHEMA_VERSION = "ip-classification-v1"
_SAFE_PATH_RE = re.compile(r"^[A-Za-z0-9_./\\:-]+$")
_EGRESS_TYPES = {"tcp", "udp", "http", "tls"}
_SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}
_CONFIDENCE_ORDER = {"A": 0, "B": 1, "C": 2}


def _safe_workspace_path(raw: str, *, var_name: str = "path") -> str:
    if not _SAFE_PATH_RE.match(raw):
        raise ValueError(f"{var_name} contains disallowed characters")
    roots: list[str] = []
    workspace = os.environ.get("GITHUB_WORKSPACE")
    if workspace:
        roots.append(os.path.realpath(workspace))
    runner_temp = os.environ.get("RUNNER_TEMP")
    if runner_temp:
        roots.append(os.path.realpath(runner_temp))
    roots.append(os.path.realpath(tempfile.gettempdir()))
    if not workspace:
        roots.append(os.path.realpath(os.getcwd()))
    resolved = os.path.realpath(raw)
    for root in roots:
        if os.path.commonpath([resolved, root]) == root:
            return resolved
    raise ValueError(f"{var_name} resolves outside trusted roots: {resolved!r}")


def _load_jsonl(path: str) -> list[dict]:
    out: list[dict] = []
    with open(path, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def _is_ipv4(value: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(value), ipaddress.IPv4Address)
    except ValueError:
        return False


def _destination_hint(event: dict) -> str:
    for key in ("fqdn", "host", "sni"):
        value = str(event.get(key) or "").strip()
        if value:
            return value
    return ""


def _score_row(*, ip: str, row: dict, otx_indicator: dict | None, dns_lookup: dict) -> dict:
    if otx_indicator is None and row.get("severity") and row.get("confidence"):
        return {
            "severity": str(row.get("severity", "Informational")),
            "confidence": str(row.get("confidence", "C")),
            "risk_score": float(row.get("risk_score", 0.0)),
            "confidence_score": float(row.get("confidence_score", 0.0)),
            "evidence_flags": [str(v) for v in row.get("evidence_flags", [])],
            "uncertainty_flags": [str(v) for v in row.get("uncertainty_flags", [])],
        }

    evidence_flags: list[str] = []
    uncertainty_flags: list[str] = []
    risk_score = 0.0
    confidence_score = 0.0
    corroboration = 0

    verdict = str(
        (otx_indicator or {}).get("verdict")
        or (otx_indicator or {}).get("classification")
        or row.get("classification")
        or "unidentified"
    )
    pulse_severity = str((otx_indicator or {}).get("pulse_severity") or row.get("pulse_severity") or "Informational")
    pulse_count = int((otx_indicator or {}).get("pulse_count") or row.get("pulse_count") or 0)
    otx_conf = str((otx_indicator or {}).get("confidence") or "").strip().lower()
    rdns = str(dns_lookup.get(ip, row.get("rdns", "")) or "")

    if verdict == "malicious":
        risk_score += 60
        confidence_score += 28
        evidence_flags.append("OTX:strong")
        corroboration += 1
        if otx_conf == "high":
            confidence_score += 18
            evidence_flags.append("OTXCONF:high")
            corroboration += 1
        elif otx_conf == "medium":
            confidence_score += 10
            evidence_flags.append("OTXCONF:medium")
        elif otx_conf == "low":
            confidence_score += 2
            evidence_flags.append("OTXCONF:low")
            uncertainty_flags.append("otx-low-confidence")
    elif verdict == "clean":
        risk_score -= 18
        confidence_score += 6
        evidence_flags.append("OTX:clean")
    else:
        uncertainty_flags.append("otx-unidentified")

    if pulse_severity == "Critical":
        risk_score += 35
        confidence_score += 16
        evidence_flags.append("PULSE:critical")
        corroboration += 1
    elif pulse_severity == "High":
        risk_score += 22
        confidence_score += 11
        evidence_flags.append("PULSE:high")
        corroboration += 1
    elif pulse_severity == "Medium":
        risk_score += 12
        confidence_score += 6
        evidence_flags.append("PULSE:medium")
    elif pulse_severity == "Low":
        risk_score += 6
        confidence_score += 3
        evidence_flags.append("PULSE:low")

    if pulse_count >= 25:
        risk_score += 12
        confidence_score += 8
        evidence_flags.append("PULSE:volume")
        corroboration += 1
    elif pulse_count >= 8:
        risk_score += 6
        confidence_score += 4
        evidence_flags.append("PULSE:repeat")

    if rdns:
        confidence_score += 6
        evidence_flags.append("RDNS:present")
        corroboration += 1
    else:
        confidence_score -= 8
        uncertainty_flags.append("rdns-missing")
        evidence_flags.append("RDNS:missing")

    fqdn = str(row.get("fqdn", "") or "")
    if not fqdn:
        confidence_score -= 5
        uncertainty_flags.append("fqdn-missing")
        evidence_flags.append("FQDN:missing")
    else:
        confidence_score += 4
        evidence_flags.append("FQDN:present")

    if corroboration >= 3:
        confidence_score += 12
        evidence_flags.append("CTX:corroborated")

    confidence_score = max(0.0, min(100.0, confidence_score))
    risk_score = max(0.0, min(100.0, risk_score))

    if confidence_score >= 70:
        confidence = "A"
    elif confidence_score >= 45:
        confidence = "B"
    else:
        confidence = "C"

    if risk_score >= 85:
        severity = "Critical"
    elif risk_score >= 65:
        severity = "High"
    elif risk_score >= 45:
        severity = "Medium"
    elif risk_score >= 25:
        severity = "Low"
    else:
        severity = "Informational"

    # Hard guardrail: no single-source critical. Critical requires high confidence
    # and corroboration across at least two independent factors.
    if severity == "Critical" and (confidence != "A" or corroboration < 2):
        severity = "High"
        uncertainty_flags.append("critical-gate-downgrade")
        evidence_flags.append("RULE:no-single-source-critical")

    return {
        "severity": severity,
        "confidence": confidence,
        "risk_score": round(risk_score, 1),
        "confidence_score": round(confidence_score, 1),
        "evidence_flags": evidence_flags,
        "uncertainty_flags": sorted(set(uncertainty_flags)),
    }


def build(*, current_jsonl: str, now: dt.datetime | None = None) -> dict:
    when = now if now is not None else dt.datetime.now(tz=dt.timezone.utc)
    events = _load_jsonl(current_jsonl)
    ip_hints: dict[str, dict[str, int]] = {}
    for ev in events:
        if ev.get("type") not in _EGRESS_TYPES:
            continue
        ip = str(ev.get("dst") or "")
        if not _is_ipv4(ip):
            continue
        hint = _destination_hint(ev)
        if ip not in ip_hints:
            ip_hints[ip] = {}
        if hint:
            ip_hints[ip][hint] = ip_hints[ip].get(hint, 0) + 1

    rows: list[dict] = []
    for ip in sorted(ip_hints.keys()):
        hints = ip_hints[ip]
        fqdn = ""
        if hints:
            # Deterministic tie-break: highest count then lexicographic.
            fqdn = sorted(hints.items(), key=lambda item: (-item[1], item[0]))[0][0]
        rows.append(
            {
                "ip": ip,
                "fqdn": fqdn,
                "rdns": "",
                "classification": "unidentified",
                "pulse_severity": "Informational",
                "pulse_count": 0,
            }
        )

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": when.isoformat().replace("+00:00", "Z"),
        "ip_classification": rows,
        "dns_lookups": {},
        "otx": None,
    }


def project_otx_classification(model: dict) -> dict:
    lookup: dict[str, dict] = {}
    otx = model.get("otx") or {}
    for row in otx.get("indicators") or []:
        ind = row.get("indicator")
        verdict = row.get("verdict")
        if ind and verdict:
            lookup[ind] = {
                "classification": verdict,
                "pulse_severity": row.get("pulse_severity", "Informational"),
                "pulse_count": row.get("pulse_count", 0),
                "confidence": row.get("confidence"),
            }
    dns_lookup = model.get("dns_lookups") or {}
    out = dict(model)
    items = []
    for row in model.get("ip_classification") or []:
        ip = row.get("ip")
        matched = lookup.get(ip)
        score = _score_row(ip=str(ip or ""), row=row, otx_indicator=matched, dns_lookup=dns_lookup)
        items.append(
            {
                "ip": ip,
                "fqdn": row.get("fqdn", ""),
                "rdns": dns_lookup.get(ip, row.get("rdns", "")),
                "classification": (matched or {}).get("classification", row.get("classification", "unidentified")),
                "pulse_severity": (matched or {}).get("pulse_severity", row.get("pulse_severity", "Informational")),
                "pulse_count": (matched or {}).get("pulse_count", row.get("pulse_count", 0)),
                "severity": score["severity"],
                "confidence": score["confidence"],
                "risk_score": score["risk_score"],
                "confidence_score": score["confidence_score"],
                "evidence_flags": score["evidence_flags"],
                "uncertainty_flags": score["uncertainty_flags"],
            }
        )
    items.sort(
        key=lambda item: (
            _SEVERITY_ORDER.get(str(item.get("severity", "Informational")), 99),
            _CONFIDENCE_ORDER.get(str(item.get("confidence", "C")), 99),
            -int(item.get("pulse_count", 0)),
            str(item.get("ip", "")),
        )
    )
    out["ip_classification"] = items
    return out


def main() -> int:
    raw_cur = os.environ.get("COLDSTEP_REPORT_CURRENT_JSONL", "")
    raw_out = os.environ.get("COLDSTEP_REPORT_MODEL_OUT", "")
    if not raw_cur or not raw_out:
        missing = []
        if not raw_cur:
            missing.append("COLDSTEP_REPORT_CURRENT_JSONL")
        if not raw_out:
            missing.append("COLDSTEP_REPORT_MODEL_OUT")
        print(f"build_ip_classification_model: missing required env vars: {', '.join(missing)}", file=sys.stderr)
        return 1
    try:
        cur = _safe_workspace_path(raw_cur, var_name="COLDSTEP_REPORT_CURRENT_JSONL")
        out = _safe_workspace_path(raw_out, var_name="COLDSTEP_REPORT_MODEL_OUT")
    except ValueError as e:
        print(f"build_ip_classification_model: refusing untrusted path: {e}", file=sys.stderr)
        return 1
    model = build(current_jsonl=cur)
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    Path(out).write_text(json.dumps(model, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
