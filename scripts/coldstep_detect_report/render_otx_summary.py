"""Append the standalone "Threat-intel verdicts" section to GITHUB_STEP_SUMMARY.

Runs after `render_step_summary.py` and after the OTX enrichment step. Kept
as a separate script so re-renders don't double-emit the capability matrix
that lives in render_step_summary.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

VERDICT_GLYPH = {
    "malicious": "🟥",
    "unidentified": "⬜",
    "clean": "🟩",
    "rate-limited": "⏱",
}
VERDICT_PRIORITY = {"malicious": 0, "unidentified": 1, "clean": 2, "rate-limited": 3}
TOP_INDICATOR_ROWS = 30


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
    status = (
        f"_Queried {api_calls} indicator(s) at {_md_cell(queried_at)} "
        f"in {wall_ms} ms"
    )
    if allowlisted:
        status += f", {allowlisted} from allowlist (skipped OTX)"
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
    # Only widen the table with a Hostname column when at least one indicator
    # in the table actually has a reverse-DNS entry; otherwise the column is
    # noise.
    show_hostname = any(dns_lookups.get(r.get("indicator", "")) for r in indicators)
    if indicators:
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
        for r in indicators:
            verdict = r.get("verdict", "")
            glyph = VERDICT_GLYPH.get(verdict, "?")
            pulses = r.get("pulse_count")
            pulses_cell = "" if pulses is None else str(pulses)
            verdict_cell = f"{glyph} {_md_cell(verdict)}"
            # Distinguish "clean by OTX validation" from "clean because we never
            # asked OTX (allowlist hit)" - the JSON island carries `source`
            # but the GFM table is the always-visible audit surface.
            if r.get("source") == "allowlist":
                reason = r.get("reason") or "?"
                verdict_cell += f" (allowlist: {_md_cell(reason)})"
            ev = _md_cell(_evidence_summary(r))
            indicator = r.get("indicator", "")
            if show_hostname:
                hostname = dns_lookups.get(indicator) or ""
                lines.append(
                    f"| `{_md_cell(indicator)}` | {_md_cell(hostname)} "
                    f"| {_md_cell(r.get('type',''))} | {verdict_cell} | {pulses_cell} | {ev} |"
                )
            else:
                lines.append(
                    f"| `{_md_cell(indicator)}` | {_md_cell(r.get('type',''))} "
                    f"| {verdict_cell} | {pulses_cell} | {ev} |"
                )
        lines.append("")
    return "\n".join(lines) + "\n"


def write_otx_summary(model: dict, summary_path: str) -> None:
    body = _section(model)
    if not body:
        return
    with open(summary_path, "a", encoding="utf-8") as f:
        f.write(body)


def main() -> int:
    model_path = os.environ.get("COLDSTEP_REPORT_MODEL_IN", "")
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY", "")
    if not model_path or not summary_path:
        missing = [n for n, v in (("COLDSTEP_REPORT_MODEL_IN", model_path),
                                  ("GITHUB_STEP_SUMMARY", summary_path)) if not v]
        print(f"render_otx_summary: missing required env vars: {', '.join(missing)}",
              file=sys.stderr)
        return 0  # never fail the detect job
    if not Path(model_path).exists():
        print(f"render_otx_summary: model file missing: {model_path}", file=sys.stderr)
        return 0
    model = json.loads(Path(model_path).read_text(encoding="utf-8"))
    write_otx_summary(model=model, summary_path=summary_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
