"""Append the standalone "Threat-intel verdicts" section to GITHUB_STEP_SUMMARY.

Runs after `render_step_summary.py` and after the OTX enrichment step. Kept
as a separate script so re-renders don't double-emit the capability matrix
that lives in render_step_summary.
"""
from __future__ import annotations

import json
import os
import re
import sys
import tempfile
from pathlib import Path

from scripts.coldstep_otx.pulse_severity import severity_rank

# Snyk Code (python/PT, CWE-23) treats every os.environ.get(...) value as
# untrusted. main() canonicalises every env-var path through this helper
# before it reaches a Path()/open() sink. Inlined per file because Snyk's
# taint analysis only recognises sanitisers that live in the same module
# as the sink.
_SAFE_PATH_RE = re.compile(r"^[A-Za-z0-9_./\\:-]+$")


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


VERDICT_GLYPH = {
    "malicious": "🟥",
    "unidentified": "⬜",
    "clean": "🟩",
    "rate-limited": "⏱",
}
VERDICT_PRIORITY = {"malicious": 0, "unidentified": 1, "clean": 2, "rate-limited": 3}
TOP_INDICATOR_ROWS = 30

TIER_LABEL = {
    "high": "🟥 High-confidence malicious",
    "medium": "🟧 Medium-confidence malicious",
    "low": "🟨 Low-confidence malicious",
}
TIER_ORDER = ("high", "medium", "low")


def _confidence_bucket(row: dict) -> str:
    """Partition key for tier tables: malicious rows by confidence tier; else null."""
    if row.get("verdict") != "malicious":
        return "null"
    return row.get("confidence") or "high"


def _why_cell(row: dict) -> str:
    reasons = row.get("confidence_reasons") or []
    if reasons:
        return "; ".join(_md_cell(str(x)) for x in reasons)
    return _md_cell(_evidence_summary(row))


def _md_cell(value: object) -> str:
    s = str(value)
    s = s.replace("\\", "\\\\").replace("|", "\\|")
    s = s.replace("\n", " ").replace("\r", " ")
    return s


def _evidence_summary(row: dict) -> str:
    ev = row.get("evidence") or []
    if not ev:
        return "—"
    parts: list[str] = []
    for e in ev[:2]:
        name = e.get("pulse_name") or e.get("pulse_id") or "?"
        fams = ", ".join(e.get("malware_families") or [])
        if fams:
            parts.append(f"{name} ({fams})")
        else:
            parts.append(name)
    if len(ev) > 2:
        parts.append(f"+{len(ev) - 2} more")
    return "; ".join(parts)


def _section(model: dict) -> str:
    otx = model.get("otx")
    if not otx:
        return ""
    lines = ["### Threat-intel verdicts (AlienVault OTX)", ""]
    if otx.get("skipped"):
        reason = otx.get("skipped_reason") or "unknown"
        lines += [f"_OTX enrichment skipped: **{_md_cell(reason)}**._", ""]
        return "\n".join(lines) + "\n"

    summary = otx.get("summary") or {}
    queried_at = otx.get("queried_at") or "?"
    wall_ms = otx.get("wall_ms") or 0
    api_calls = otx.get("api_calls") or 0
    allowlisted = otx.get("allowlisted") or 0
    partial = otx.get("partial_results")
    filter_drops = int(otx.get("filter_drops") or 0)
    status = (
        f"_Queried {api_calls} indicator(s) at {_md_cell(queried_at)} "
        f"in {wall_ms} ms"
    )
    if allowlisted:
        status += f", {allowlisted} from allowlist (skipped OTX)"
    if filter_drops:
        status += f", filtered {filter_drops} pulse(s)"
    if partial:
        status += " (partial — wall budget exhausted)"
    status += "._"
    lines += [status, ""]

    counts = [
        ("malicious", summary.get("malicious", 0)),
        ("unidentified", summary.get("unidentified", 0)),
        ("clean", summary.get("clean", 0)),
    ]
    if any(c for _, c in counts):
        lines += [
            "```mermaid",
            "pie showData",
            '  title Verdicts',
        ]
        for label, count in counts:
            if count > 0:
                lines.append(f'  "{label}" : {count}')
        lines += ["```", ""]

    indicators = sorted(
        otx.get("indicators") or [],
        key=lambda r: (VERDICT_PRIORITY.get(r.get("verdict", ""), 99),
                       r.get("indicator", "")),
    )[:TOP_INDICATOR_ROWS]
    dns_lookups = model.get("dns_lookups") or {}
    show_hostname = any(dns_lookups.get(r.get("indicator", "")) for r in indicators)

    buckets: dict[str, list[dict]] = {
        "high": [], "medium": [], "low": [], "null": [],
    }
    for r in indicators:
        buckets[_confidence_bucket(r)].append(r)

    def _append_malicious_tier_table(tier_key: str, tier_rows: list[dict]) -> None:
        nonlocal lines
        tier_rows = sorted(
            tier_rows,
            key=lambda r: (
                severity_rank(str(r.get("pulse_severity") or "Informational")),
                str(r.get("indicator", "")),
            ),
        )
        label = TIER_LABEL[tier_key]
        open_attr = " open" if tier_key == "high" else ""
        lines.append(f"<details{open_attr}>")
        lines.append(f"<summary>{label} ({len(tier_rows)})</summary>")
        lines.append("")
        if show_hostname:
            lines += [
                "| Indicator | Hostname | Type | Pulses | Severity | Why |",
                "|---|---|---|---:|---|---|",
            ]
        else:
            lines += [
                "| Indicator | Type | Pulses | Severity | Why |",
                "|---|---|---:|---|---|",
            ]
        for r in tier_rows:
            indicator = r.get("indicator", "")
            pulses = r.get("pulse_count")
            pulses_cell = "" if pulses is None else str(pulses)
            sev = _md_cell(str(r.get("pulse_severity") or ""))
            why = _why_cell(r)
            if show_hostname:
                hostname = dns_lookups.get(indicator) or ""
                lines.append(
                    f"| `{_md_cell(indicator)}` | {_md_cell(hostname)} "
                    f"| {_md_cell(r.get('type', ''))} | {pulses_cell} | {sev} | {why} |"
                )
            else:
                lines.append(
                    f"| `{_md_cell(indicator)}` | {_md_cell(r.get('type', ''))} "
                    f"| {pulses_cell} | {sev} | {why} |"
                )
        lines.append("</details>")
        lines.append("")

    for tier_key in TIER_ORDER:
        tier_rows = buckets[tier_key]
        if tier_rows:
            _append_malicious_tier_table(tier_key, tier_rows)

    null_rows = buckets["null"]
    if null_rows:
        lines.append("<details>")
        lines.append(f"<summary>Other verdicts ({len(null_rows)})</summary>")
        lines.append("")
        if show_hostname:
            lines += [
                "| Indicator | Hostname | Type | Verdict | Pulses | Top evidence |",
                "|---|---|---|---|---:|---|",
            ]
        else:
            lines += [
                "| Indicator | Type | Verdict | Pulses | Top evidence |",
                "|---|---|---|---:|---|",
            ]
        for r in null_rows:
            verdict = r.get("verdict", "")
            glyph = VERDICT_GLYPH.get(verdict, "?")
            pulses = r.get("pulse_count")
            pulses_cell = "" if pulses is None else str(pulses)
            verdict_cell = f"{glyph} {_md_cell(verdict)}"
            if r.get("source") == "allowlist":
                reason = r.get("reason") or "?"
                verdict_cell += f" (allowlist: {_md_cell(reason)})"
            ev = _md_cell(_evidence_summary(r))
            indicator = r.get("indicator", "")
            if show_hostname:
                hostname = dns_lookups.get(indicator) or ""
                lines.append(
                    f"| `{_md_cell(indicator)}` | {_md_cell(hostname)} "
                    f"| {_md_cell(r.get('type', ''))} | {verdict_cell} | {pulses_cell} | {ev} |"
                )
            else:
                lines.append(
                    f"| `{_md_cell(indicator)}` | {_md_cell(r.get('type', ''))} "
                    f"| {verdict_cell} | {pulses_cell} | {ev} |"
                )
        lines.append("</details>")
        lines.append("")

    filtered_entries = otx.get("filtered_pulses") or []
    if filter_drops or filtered_entries:
        lines.append("<details>")
        lines.append("<summary>Filter audit</summary>")
        lines.append("")
        if filter_drops:
            lines.append(f"- Dropped **{filter_drops}** pulse row(s) during filtering.")
        for entry in filtered_entries[:20]:
            if isinstance(entry, dict):
                nm = entry.get("pulse_name") or entry.get("pulse_id") or "?"
                lines.append(f"- {_md_cell(nm)}")
            else:
                lines.append(f"- {_md_cell(entry)}")
        if len(filtered_entries) > 20:
            lines.append(f"- _…and {len(filtered_entries) - 20} more._")
        lines.append("</details>")
        lines.append("")

    return "\n".join(lines) + "\n"


def write_otx_summary(model: dict, summary_path: str) -> None:
    body = _section(model)
    if not body:
        return
    with open(summary_path, "a", encoding="utf-8") as f:
        f.write(body)


def main() -> int:
    raw_model_path = os.environ.get("COLDSTEP_REPORT_MODEL_IN", "")
    raw_summary_path = os.environ.get("GITHUB_STEP_SUMMARY", "")
    if not raw_model_path or not raw_summary_path:
        missing = [n for n, v in (("COLDSTEP_REPORT_MODEL_IN", raw_model_path),
                                  ("GITHUB_STEP_SUMMARY", raw_summary_path)) if not v]
        print(f"render_otx_summary: missing required env vars: {', '.join(missing)}",
              file=sys.stderr)
        return 0  # never fail the detect job
    try:
        model_path = _safe_workspace_path(raw_model_path, var_name="COLDSTEP_REPORT_MODEL_IN")
        summary_path = _safe_workspace_path(raw_summary_path, var_name="GITHUB_STEP_SUMMARY")
    except ValueError as e:
        print(f"render_otx_summary: refusing untrusted path: {e}", file=sys.stderr)
        return 0
    if not Path(model_path).exists():
        print(f"render_otx_summary: model file missing: {model_path}", file=sys.stderr)
        return 0
    model = json.loads(Path(model_path).read_text(encoding="utf-8"))
    write_otx_summary(model=model, summary_path=summary_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
