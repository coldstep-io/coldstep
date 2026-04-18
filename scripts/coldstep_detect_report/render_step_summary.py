"""Render the Tier-1 step-summary surface from report-model.json.

Output: GFM Markdown + Mermaid blocks (xychart-beta, sankey-beta).
Constraint: must stay well under 1 MiB and rely on no `<script>`.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

# warn / unknown (❔) reserved for future capability statuses; v1 capability_matrix only emits pass | fail.
STATUS_PILL = {"pass": "🟢", "warn": "🟡", "fail": "🔴"}

TOP_EVENTS_N = 10
TOP_SANKEY_EDGES = 30
TOP_DIFF_ROWS = 20


def _md_cell(value: object) -> str:
    """Escape a value for safe inclusion in a GFM table cell.

    GFM uses `|` as the column separator; backslash-escape it. Newlines collapse
    to a single space because tables can't span lines. Backslashes get doubled
    so that an existing `\\|` in the source survives a round trip.
    """
    s = str(value)
    s = s.replace("\\", "\\\\").replace("|", "\\|")
    s = s.replace("\n", " ").replace("\r", " ")
    return s


def _csv_field(value: object) -> str:
    """Mermaid sankey-beta uses CSV. Quote per RFC 4180 if the field contains , " \\n or leading/trailing whitespace."""
    s = str(value)
    if any(c in s for c in ',"\n\r') or s != s.strip():
        return '"' + s.replace('"', '""') + '"'
    return s


def _xy_axis_label(value: object) -> str:
    # xychart-beta uses double-quoted axis labels; embedded " would break the block.
    return '"' + str(value).replace('"', "'") + '"'


def _capability_matrix_md(model: dict) -> str:
    lines = [
        "### Detect Capability Matrix (GitHub-hosted ubuntu-latest)",
        "",
        "| Capability | Status | Evidence |",
        "|---|---|---|",
    ]
    for row in model["capability_matrix"]:
        pill = STATUS_PILL.get(row["status"], "❔")
        label = _md_cell(row["label"])
        evidence = f"`type:{_md_cell(row['id'])}` × {row['evidence_count']}"
        lines.append(f"| {label} | {pill} | {evidence} |")
    lines += ["", "_Legend: 🟢 pass, 🟡 investigate, 🔴 fail_", ""]
    return "\n".join(lines)


def _events_xychart_md(model: dict) -> str:
    rows = model["events_by_type"][:TOP_EVENTS_N]
    if not rows:
        return ""
    types = [r["type"] for r in rows]
    counts = [r["count"] for r in rows]
    bars = ", ".join(str(c) for c in counts)
    xs = ", ".join(_xy_axis_label(t) for t in types)
    return (
        "### Events by type (current run)\n\n"
        "```mermaid\n"
        "xychart-beta\n"
        '  title "Coldstep events by type"\n'
        f"  x-axis [{xs}]\n"
        '  y-axis "Count"\n'
        f"  bar [{bars}]\n"
        "```\n"
    )


def _egress_sankey_md(model: dict) -> str:
    edges = model["egress_sankey"][:TOP_SANKEY_EDGES]
    if not edges:
        return ""
    body = "\n".join(
        f'  {_csv_field(e["source"])},{_csv_field(e["target"])},{e["value"]}'
        for e in edges
    )
    return (
        "### Egress flow (host → policy)\n\n"
        "```mermaid\n"
        "sankey-beta\n"
        f"{body}\n"
        "```\n"
    )


def _diff_md(model: dict) -> str:
    diff = model["diff"]
    if diff.get("status") != "ok":
        return f"### Previous Run Diff\n\n_Diff unavailable: {diff.get('reason', 'unknown')}._\n"
    lines = ["### Previous Run Diff", ""]
    # Note: count_label is only used for the new/gone single-count tables;
    # the changed table uses a fixed 3-column layout below.
    for title, key, count_label in (
        ("New traffic (in current, not in baseline)", "traffic_new", "Current"),
        ("Missing traffic (in baseline, not in current)", "traffic_gone", "Baseline"),
        ("Changed multiplicity", "traffic_changed", ""),
    ):
        rows = diff.get(key, [])[:TOP_DIFF_ROWS]
        lines += [f"#### {title}", ""]
        if not rows:
            lines += ["_None._", ""]
            continue
        if key == "traffic_changed":
            lines += ["| Baseline | Current | Fingerprint |", "|---:|---:|---|"]
            for r in rows:
                fp = _md_cell(r['fingerprint'])
                lines.append(f"| {r['baseline']} | {r['current']} | `{fp}` |")
        else:
            lines += [f"| {count_label} count | Fingerprint |", "|---:|---|"]
            for r in rows:
                fp = _md_cell(r['fingerprint'])
                lines.append(f"| {r['count']} | `{fp}` |")
        lines.append("")
    return "\n".join(lines)


def write_summary(model: dict, summary_path: str) -> None:
    parts = [
        _capability_matrix_md(model),
        _events_xychart_md(model),
        _egress_sankey_md(model),
        _diff_md(model),
    ]
    body = "\n".join(p for p in parts if p)
    if not body.endswith("\n"):
        body += "\n"
    # Append: $GITHUB_STEP_SUMMARY may already contain output from earlier steps in the same job.
    with open(summary_path, "a", encoding="utf-8") as f:
        f.write(body)


def main() -> int:
    model_path = os.environ.get("COLDSTEP_REPORT_MODEL_IN", "")
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY", "")
    if not model_path or not summary_path:
        missing = [
            name for name, val in
            (("COLDSTEP_REPORT_MODEL_IN", model_path), ("GITHUB_STEP_SUMMARY", summary_path))
            if not val
        ]
        print(f"render_step_summary: missing required env vars: {', '.join(missing)}", file=sys.stderr)
        return 1
    model = json.loads(Path(model_path).read_text(encoding="utf-8"))
    write_summary(model=model, summary_path=summary_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
