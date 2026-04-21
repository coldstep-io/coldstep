"""Render IP/FQDN/rDNS classification summary for detect-dev."""
from __future__ import annotations

import json
import os
import re
import sys
import tempfile
from pathlib import Path

# Support direct script execution (`python3 scripts/.../render_ip_classification_summary.py`)
# by ensuring repo root is on sys.path before importing `scripts.*`.
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from scripts.coldstep_detect_report.build_ip_classification_model import (
    classify_destination_context,
    project_otx_classification,
)

_SAFE_PATH_RE = re.compile(r"^[A-Za-z0-9_./\\:-]+$")
PULSE_GLYPH = {
    "Critical": "🟥",
    "High": "🟧",
    "Medium": "🟨",
    "Low": "🟩",
    "Informational": "🟩",
}
SEVERITY_GLYPH = {
    "Critical": "🟥",
    "High": "🟧",
    "Medium": "🟨",
    "Low": "🟩",
    "Informational": "🟩",
}
_SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}
_CONFIDENCE_ORDER = {"A": 0, "B": 1, "C": 2}
_PULSE_SEVERITY_ORDER = ("Critical", "High", "Medium", "Low", "Informational")
_KNOWN_INFRA_SUFFIXES = (
    ".githubapp.com",
    ".cloudapp.azure.com",
    ".google.com",
    ".google",
)


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


def _spark(value: int, max_value: int, *, width: int = 12) -> str:
    if max_value <= 0 or value <= 0:
        return " " * width
    filled = max(1, int(round((value / max_value) * width)))
    filled = min(width, filled)
    return ("#" * filled).ljust(width)


def _is_known_infra_row(row: dict) -> bool:
    context = str(row.get("context", "") or "")
    if context in {"Localhost", "Platform DNS", "Known Public Resolver"}:
        return True
    ip = str(row.get("ip", ""))
    fqdn = str(row.get("fqdn", "")).lower()
    rdns = str(row.get("rdns", "")).lower()
    if ip.startswith("127."):
        return True
    if ip == "168.63.129.16":
        return True
    names = [fqdn, rdns]
    for name in names:
        if not name:
            continue
        if any(name.endswith(suffix) for suffix in _KNOWN_INFRA_SUFFIXES):
            return True
    return False


def render_markdown(model: dict) -> str:
    projected = project_otx_classification(model)
    rows = projected.get("ip_classification") or []
    rows = sorted(
        rows,
        key=lambda item: (
            _SEVERITY_ORDER.get(str(item.get("severity", "Informational")), 99),
            _CONFIDENCE_ORDER.get(str(item.get("confidence", "C")), 99),
            -int(item.get("pulse_count", 0)),
            str(item.get("ip", "")),
        ),
    )
    top = rows[0] if rows else {}
    top_sev = str(top.get("severity", "Informational"))
    top_conf = str(top.get("confidence", "C"))
    top_flags = [str(f) for f in top.get("evidence_flags", [])[:3]]
    recommendation = "monitor"
    if top_sev in {"Critical", "High"}:
        recommendation = "contain"
    elif top_sev == "Medium":
        recommendation = "investigate"

    suspicious_rows = [
        row for row in rows if str(row.get("severity", "Informational")) not in {"Informational", "Low"}
    ]
    known_infra_rows = [row for row in rows if _is_known_infra_row(row)]
    lines = [
        "## Coldstep detect - IP classification",
        "",
        "### Decision banner",
        "",
        f"- Highest severity: {SEVERITY_GLYPH.get(top_sev, '⬜')} {top_sev}",
        f"- Confidence grade: {top_conf}",
        f"- Why: {', '.join(top_flags) if top_flags else 'insufficient corroborated signal'}",
        f"- Immediate action: {recommendation}",
        f"- Triage signal rows: {len(suspicious_rows)} / {len(rows)}",
        f"- Known infra rows: {len(known_infra_rows)}",
        "",
        "| IP | FQDN | rDNS | Classification | Context | Severity | Confidence | Evidence flags | Pulse severity | Pulse count |",
        "|---|---|---|---|---|---|---|---|---|---:|",
    ]
    uncertainty_rows = 0
    top_uncertainty: dict[str, int] = {}
    for row in rows:
        severity = str(row.get("pulse_severity", "Informational"))
        sev_with_glyph = f"{PULSE_GLYPH.get(severity, '⬜')} {severity}"
        risk_sev = str(row.get("severity", "Informational"))
        risk_with_glyph = f"{SEVERITY_GLYPH.get(risk_sev, '⬜')} {risk_sev}"
        evidence_flags = ", ".join(str(f) for f in row.get("evidence_flags", [])) or "-"
        for flag in row.get("uncertainty_flags", []) or []:
            flag_s = str(flag)
            top_uncertainty[flag_s] = top_uncertainty.get(flag_s, 0) + 1
        if row.get("uncertainty_flags"):
            uncertainty_rows += 1
        lines.append(
            f"| {row.get('ip', '')} | {row.get('fqdn', '')} | {row.get('rdns', '')} | "
            f"{row.get('classification', 'unidentified')} | "
            f"{row.get('context') or classify_destination_context(ip=str(row.get('ip', '') or ''), fqdn=str(row.get('fqdn', '') or ''), rdns=str(row.get('rdns', '') or ''))} | "
            f"{risk_with_glyph} | {row.get('confidence', 'C')} | "
            f"{evidence_flags} | {sev_with_glyph} | {row.get('pulse_count', 0)} |"
        )
    if not rows:
        lines.append("| (none) |  |  | unidentified | External | 🟩 Informational | C |  | 🟩 Informational | 0 |")

    lines.extend(
        [
            "",
            "### Known infra snapshot",
            "",
            f"- Rows classified as baseline infra/noise candidates: {len(known_infra_rows)}",
        ]
    )
    if known_infra_rows:
        top_known = sorted(
            known_infra_rows,
            key=lambda item: (-int(item.get("pulse_count", 0)), str(item.get("ip", ""))),
        )[:5]
        for row in top_known:
            label = str(row.get("ip", ""))
            fqdn = str(row.get("fqdn", ""))
            if fqdn:
                label = f"{label} ({fqdn})"
            lines.append(f"- `{label}` pulse={int(row.get('pulse_count', 0))}")
    else:
        lines.append("- No known infra rows identified in this run.")

    pulse_totals: dict[str, int] = {name: 0 for name in _PULSE_SEVERITY_ORDER}
    for row in rows:
        sev = str(row.get("pulse_severity", "Informational"))
        if sev not in pulse_totals:
            pulse_totals[sev] = 0
        pulse_totals[sev] += int(row.get("pulse_count", 0))
    max_pulse = max(pulse_totals.values()) if pulse_totals else 0
    total_pulses = sum(pulse_totals.values())
    lines.extend(
        [
            "",
            "### OTX pulse chart",
            "",
            f"- Total pulse count observed: {total_pulses}",
            "",
            "| Pulse severity | Pulse volume | Count |",
            "|---|---|---:|",
        ]
    )
    for sev in _PULSE_SEVERITY_ORDER:
        volume = pulse_totals.get(sev, 0)
        glyph = PULSE_GLYPH.get(sev, "⬜")
        lines.append(f"| {glyph} {sev} | `{_spark(volume, max_pulse)}` | {volume} |")

    top_pulse_rows = [r for r in rows if int(r.get("pulse_count", 0)) > 0]
    top_pulse_rows.sort(key=lambda item: (-int(item.get("pulse_count", 0)), str(item.get("ip", ""))))
    lines.extend(
        [
            "",
            "#### Top pulse-backed destinations",
            "",
        ]
    )
    if top_pulse_rows:
        max_top = int(top_pulse_rows[0].get("pulse_count", 0))
        for row in top_pulse_rows[:5]:
            ip = str(row.get("ip", ""))
            fqdn = str(row.get("fqdn", ""))
            pulse_count = int(row.get("pulse_count", 0))
            label = f"{ip} ({fqdn})" if fqdn else ip
            lines.append(f"- `{label}` `{_spark(pulse_count, max_top)}` {pulse_count}")
    else:
        lines.append("- No pulse-backed destinations in this run.")

    lines.extend(
        [
            "",
            "### Uncertainty and contradictions",
            "",
            f"- Rows with uncertainty flags: {uncertainty_rows}",
            "- Top uncertainty drivers: "
            + (
                ", ".join(
                    f"{name} ({count})"
                    for name, count in sorted(top_uncertainty.items(), key=lambda item: (-item[1], item[0]))[:3]
                )
                if top_uncertainty
                else "none"
            ),
            "",
            "### Action queue",
            "",
        ]
    )
    if top_sev in {"Critical", "High"}:
        lines.append("- [IR] escalate top destination and start containment verification.")
        lines.append("- [SecEng] validate indicator confidence and check cloud/demotion context.")
        lines.append("- [Dev] confirm expected egress path and investigate drift.")
    elif top_sev == "Medium":
        lines.append("- [SecEng] investigate ambiguous signals and enrichment gaps.")
        lines.append("- [Dev] verify destination intent against current workflow behavior.")
    else:
        lines.append("- [Dev] monitor; no urgent containment action required.")
        lines.append("- [SecEng] track trend changes across subsequent runs.")
    lines.append("")
    return "\n".join(lines)


def write_summary(*, model: dict, summary_path: str) -> None:
    body = render_markdown(model)
    with open(summary_path, "a", encoding="utf-8") as f:
        f.write(body + "\n")


def main() -> int:
    raw_model_path = os.environ.get("COLDSTEP_REPORT_MODEL_IN", "")
    raw_summary_path = os.environ.get("GITHUB_STEP_SUMMARY", "")
    if not raw_model_path or not raw_summary_path:
        missing = []
        if not raw_model_path:
            missing.append("COLDSTEP_REPORT_MODEL_IN")
        if not raw_summary_path:
            missing.append("GITHUB_STEP_SUMMARY")
        print(f"render_ip_classification_summary: missing required env vars: {', '.join(missing)}", file=sys.stderr)
        return 1
    try:
        model_path = _safe_workspace_path(raw_model_path, var_name="COLDSTEP_REPORT_MODEL_IN")
        summary_path = _safe_workspace_path(raw_summary_path, var_name="GITHUB_STEP_SUMMARY")
    except ValueError as e:
        print(f"render_ip_classification_summary: refusing untrusted path: {e}", file=sys.stderr)
        return 1
    model = json.loads(Path(model_path).read_text(encoding="utf-8"))
    body = render_markdown(model)
    with open(summary_path, "a", encoding="utf-8") as f:
        f.write(body + "\n")
    raw_copy_path = os.environ.get("COLDSTEP_REPORT_SUMMARY_OUT", "").strip()
    if raw_copy_path:
        try:
            copy_path = _safe_workspace_path(raw_copy_path, var_name="COLDSTEP_REPORT_SUMMARY_OUT")
        except ValueError as e:
            print(f"render_ip_classification_summary: refusing untrusted summary copy path: {e}", file=sys.stderr)
            return 1
        Path(copy_path).write_text(body + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
