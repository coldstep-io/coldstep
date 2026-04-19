"""Render the Tier-1 step-summary surface from report-model.json.

Output: GFM Markdown + Mermaid blocks (xychart-beta, sankey-beta).
Constraint: must stay well under 1 MiB and rely on no `<script>`.
"""
from __future__ import annotations

import json
import os
import re
import sys
import tempfile
from pathlib import Path

from scripts.coldstep_otx.pulse_severity import severity_rank

# warn / unknown (❔) reserved for future capability statuses; v1 capability_matrix only emits pass | fail.
STATUS_PILL = {"pass": "🟢", "warn": "🟡", "fail": "🔴"}

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

# OTX verdict glyphs for the per-entry verdict cell in diff bucket tables.
VERDICT_GLYPH = {
    "malicious": "🟥",
    "unidentified": "⬜",
    "clean": "🟩",
    "rate-limited": "⏱",
}
VERDICT_PRIORITY = {"malicious": 0, "unidentified": 1, "clean": 2, "rate-limited": 3}

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


def _highest_pulse_signal(indicators: list) -> str | None:
    """Return worst pulse_severity among malicious rows, or None."""
    best = None
    best_rank = 99
    for r in indicators:
        if r.get("verdict") != "malicious":
            continue
        ps = str(r.get("pulse_severity") or "")
        if not ps or ps == "Informational":
            continue
        rk = severity_rank(ps)
        if rk < best_rank:
            best_rank = rk
            best = ps
    return best


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


def _host_label(host: str, dns_lookups: dict) -> str:
    """Decorate a host node with its rDNS hostname when known.

    `8.8.8.8` -> `8.8.8.8 (dns.google)`. Hosts that aren't IPs (or that have
    no PTR) come back unchanged - the renderer doesn't need to know the type,
    it just looks up the literal string in the rDNS map. Quoting for CSV is
    handled at emission time by `_csv_field`.
    """
    if not host:
        return host
    name = (dns_lookups or {}).get(host)
    return f"{host} ({name})" if name else host


# Synthetic verdict bucket for indicators OTX hasn't seen (partial budget,
# IPv6, unsupported type, allowlist-but-no-OTX-row, or no indicators on the
# edge at all). Keeps the 3-column visualization mass-balanced.
_UNVERIFIED = "unverified"


def _egress_sankey_md(model: dict) -> str:
    edges = model["egress_sankey"][:TOP_SANKEY_EDGES]
    if not edges:
        return ""
    dns_lookups = model.get("dns_lookups") or {}
    verdict_lookup = _verdict_lookup(model)
    # 3-column pivot only when OTX produced verdicts; otherwise keep the
    # classic 2-column sankey so a no-OTX run isn't weirdly wider.
    if verdict_lookup:
        title = "### Egress flow (host → verdict → policy)\n\n"
        rows: list[str] = []
        for e in edges:
            src_field = _csv_field(_host_label(e["source"], dns_lookups))
            tgt_field = _csv_field(e["target"])
            value = e["value"]
            verdict = (_entry_verdict(e, verdict_lookup) or _UNVERIFIED)
            v_field = _csv_field(verdict)
            rows.append(f"  {src_field},{v_field},{value}")
            rows.append(f"  {v_field},{tgt_field},{value}")
        body = "\n".join(rows)
    else:
        title = "### Egress flow (host → policy)\n\n"
        body = "\n".join(
            f'  {_csv_field(_host_label(e["source"], dns_lookups))},'
            f'{_csv_field(e["target"])},{e["value"]}'
            for e in edges
        )
    return (
        f"{title}"
        "```mermaid\n"
        "sankey-beta\n"
        f"{body}\n"
        "```\n"
    )


def _verdict_lookup(model: dict) -> dict[str, str]:
    """Build indicator -> verdict map; empty dict if otx absent or skipped."""
    otx = model.get("otx")
    if not otx or otx.get("skipped"):
        return {}
    out: dict[str, str] = {}
    for row in otx.get("indicators", []):
        ind = row.get("indicator")
        v = row.get("verdict")
        if ind and v:
            out[ind] = v
    return out


def _entry_verdict(entry: dict, lookup: dict[str, str]) -> str:
    """Highest-severity verdict among an entry's indicators (malicious wins)."""
    if not lookup:
        return ""
    candidates = [lookup[i] for i in (entry.get("indicators") or []) if i in lookup]
    if not candidates:
        return ""
    return min(candidates, key=lambda v: VERDICT_PRIORITY.get(v, 99))


def _verdict_cell(verdict: str) -> str:
    if not verdict:
        return ""
    return f"{VERDICT_GLYPH.get(verdict, '?')} {verdict}"


def _diff_md(model: dict) -> str:
    diff = model["diff"]
    if diff.get("status") != "ok":
        return f"### Previous Run Diff\n\n_Diff unavailable: {diff.get('reason', 'unknown')}._\n"
    lookup = _verdict_lookup(model)
    show_verdict = bool(lookup)
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
            if show_verdict:
                lines += ["| Baseline | Current | Verdict | Fingerprint |",
                          "|---:|---:|---|---|"]
            else:
                lines += ["| Baseline | Current | Fingerprint |", "|---:|---:|---|"]
            for r in rows:
                fp = _md_cell(r['fingerprint'])
                if show_verdict:
                    v_cell = _md_cell(_verdict_cell(_entry_verdict(r, lookup)))
                    lines.append(f"| {r['baseline']} | {r['current']} | {v_cell} | `{fp}` |")
                else:
                    lines.append(f"| {r['baseline']} | {r['current']} | `{fp}` |")
        else:
            if show_verdict:
                lines += [f"| {count_label} count | Verdict | Fingerprint |",
                          "|---:|---|---|"]
            else:
                lines += [f"| {count_label} count | Fingerprint |", "|---:|---|"]
            for r in rows:
                fp = _md_cell(r['fingerprint'])
                if show_verdict:
                    v_cell = _md_cell(_verdict_cell(_entry_verdict(r, lookup)))
                    lines.append(f"| {r['count']} | {v_cell} | `{fp}` |")
                else:
                    lines.append(f"| {r['count']} | `{fp}` |")
        lines.append("")
    return "\n".join(lines)


def _otx_highest_pulse_signal_md(model: dict) -> str:
    """Short heading when OTX ran and at least one malicious row has pulse severity."""
    otx = model.get("otx")
    if not otx or otx.get("skipped"):
        return ""
    indicators = otx.get("indicators") or []
    malicious_n = sum(1 for r in indicators if r.get("verdict") == "malicious")
    if malicious_n <= 0:
        return ""
    worst = _highest_pulse_signal(indicators)
    if worst is None:
        return ""
    return (
        "### Threat intel · OTX pulse signal\n\n"
        f"Highest pulse signal among malicious indicators: **{_md_cell(worst)}**.\n\n"
    )


def write_summary(model: dict, summary_path: str) -> None:
    parts = [
        _capability_matrix_md(model),
        _otx_highest_pulse_signal_md(model),
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
    raw_model_path = os.environ.get("COLDSTEP_REPORT_MODEL_IN", "")
    raw_summary_path = os.environ.get("GITHUB_STEP_SUMMARY", "")
    if not raw_model_path or not raw_summary_path:
        missing = [
            name for name, val in
            (("COLDSTEP_REPORT_MODEL_IN", raw_model_path), ("GITHUB_STEP_SUMMARY", raw_summary_path))
            if not val
        ]
        print(f"render_step_summary: missing required env vars: {', '.join(missing)}", file=sys.stderr)
        return 1
    try:
        model_path = _safe_workspace_path(raw_model_path, var_name="COLDSTEP_REPORT_MODEL_IN")
        summary_path = _safe_workspace_path(raw_summary_path, var_name="GITHUB_STEP_SUMMARY")
    except ValueError as e:
        print(f"render_step_summary: refusing untrusted path: {e}", file=sys.stderr)
        return 1
    model = json.loads(Path(model_path).read_text(encoding="utf-8"))
    write_summary(model=model, summary_path=summary_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
