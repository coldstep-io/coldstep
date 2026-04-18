#!/usr/bin/env python3
"""
Append a GitHub Actions job-summary section comparing two Coldstep JSONL files.

Traffic fingerprints intentionally omit pid / tgid / thread_id / comm / seq / ts so
consecutive runs can be compared on egress shape (TCP/UDP/HTTP/TLS/deny).
"""

from __future__ import annotations

import collections
import hashlib
import json
import os
from pathlib import PurePosixPath
import sys


def load_events(path: str) -> tuple[list[dict], int, int]:
    """Load JSONL objects; skip empty lines after strip.

    Returns:
        events: successfully parsed JSON objects (order preserved).
        invalid: count of non-empty lines that raised json.JSONDecodeError.
        lines: count of non-empty lines after strip (attempted JSON lines).
    """
    out: list[dict] = []
    invalid = 0
    lines = 0
    try:
        with open(path, "r", encoding="utf-8") as f:
            for raw in f:
                line = raw.strip()
                if not line:
                    continue
                lines += 1
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    invalid += 1
    except OSError:
        return [], 0, 0
    return out, invalid, lines


def traffic_fingerprint(ev: dict) -> str | None:
    t = ev.get("type")
    if t == "tcp":
        return (
            "traffic » tcp » "
            f"{ev.get('dst', '')} » {ev.get('dport', '')} » "
            f"{(ev.get('fqdn') or '')} » {ev.get('direction', '')} » {ev.get('policy', '')}"
        )
    if t == "udp":
        return (
            "traffic » udp » "
            f"{ev.get('dst', '')} » {ev.get('dport', '')} » "
            f"{(ev.get('fqdn') or '')} » {ev.get('direction', '')} » {ev.get('policy', '')}"
        )
    if t == "http":
        full_path = ev.get("path") or ""
        path = full_path
        if len(full_path) > 120:
            path = full_path[:120] + "\u2026"
        # Keep summary readable, but retain full-path entropy for stable diffing.
        path_hash = hashlib.sha256(full_path.encode("utf-8")).hexdigest()[:10]
        return (
            "traffic » http » "
            f"{ev.get('dst', '')} » {ev.get('dport', '')} » "
            f"{(ev.get('host') or '')} » {ev.get('method', '')} » "
            f"{path} » h={path_hash} » {ev.get('policy', '')}"
        )
    if t == "tls":
        return (
            "traffic » tls » "
            f"{ev.get('dst', '')} » {ev.get('dport', '')} » "
            f"{(ev.get('sni') or '')} » {ev.get('policy', '')}"
        )
    if t == "deny":
        return (
            "traffic » deny » "
            f"{ev.get('protocol', '')} » {ev.get('dst', '')} » {ev.get('dport', '')} » "
            f"{ev.get('reason', '')} » {ev.get('mode', '')}"
        )
    return None


def other_fingerprint(ev: dict) -> str | None:
    t = ev.get("type")
    if t == "exec":
        exe = (ev.get("exe") or "").strip()
        base = PurePosixPath(exe).name if exe else ""
        return f"other » exec » {base}"
    if t == "fs_event":
        op = ev.get("op", "")
        path = (ev.get("path") or "").strip()
        base = PurePosixPath(path).name if path else ""
        return f"other » fs_event » {op} » {base}"
    if t == "proc_fork":
        return (
            "other » proc_fork » "
            f"{(ev.get('parent_comm') or '')} » {(ev.get('child_comm') or '')}"
        )
    return None


def count_fps(events: list[dict]) -> tuple[collections.Counter[str], collections.Counter[str], collections.Counter[str]]:
    traffic: collections.Counter[str] = collections.Counter()
    other: collections.Counter[str] = collections.Counter()
    unclassified: collections.Counter[str] = collections.Counter()
    for ev in events:
        fp = traffic_fingerprint(ev)
        if fp is not None:
            traffic[fp] += 1
            continue
        fp2 = other_fingerprint(ev)
        if fp2 is not None:
            other[fp2] += 1
            continue
        unclassified[str(ev.get("type") or "<missing-type>")] += 1
    return traffic, other, unclassified


def multiset_diff(
    prev_c: collections.Counter[str],
    curr_c: collections.Counter[str],
) -> tuple[list[tuple[int, str]], list[tuple[int, str]], list[tuple[int, int, str]]]:
    new: list[tuple[int, str]] = []
    gone: list[tuple[int, str]] = []
    chg: list[tuple[int, int, str]] = []
    keys = set(prev_c) | set(curr_c)
    for k in keys:
        a = prev_c.get(k, 0)
        b = curr_c.get(k, 0)
        if a == 0 and b > 0:
            new.append((b, k))
        elif b == 0 and a > 0:
            gone.append((a, k))
        elif a != b:
            chg.append((a, b, k))
    new.sort(key=lambda x: (-x[0], x[1]))
    gone.sort(key=lambda x: (-x[0], x[1]))
    chg.sort(key=lambda x: (-abs(x[1] - x[0]), x[2]))
    return new, gone, chg


def write_table(
    out,
    title: str,
    rows: list[tuple],
    cols: list[str],
) -> None:
    out.write("\n")
    out.write(f"#### {title}\n\n")
    if not rows:
        out.write("_None._\n")
        return
    out.write("| " + " | ".join(cols) + " |\n")
    out.write("|" + "|".join(["---"] * len(cols)) + "|\n")
    for r in rows:
        cells: list[str] = []
        for c in r:
            if isinstance(c, str):
                c = c.replace("|", "\\|")
                cells.append(f"`{c}`")
            else:
                cells.append(str(c))
        out.write("| " + " | ".join(cells) + " |\n")


def main() -> int:
    summary_path = os.environ.get("NS_SUMMARY", "")
    base_path = os.environ.get("NS_BASELINE", "")
    cur_path = os.environ.get("NS_CURRENT", "")
    marker = os.environ.get("NS_MARKER", "coldstep-prev-diff")
    strict_mode = os.environ.get("COLDSTEP_DIFF_STRICT", "0").strip() == "1"

    if not summary_path or not base_path or not cur_path:
        return 1

    base_ev, base_invalid, base_lines = load_events(base_path)
    cur_ev, cur_invalid, cur_lines = load_events(cur_path)
    if not base_ev or not cur_ev:
        parse_health = "degraded" if (base_invalid or cur_invalid) else "ok"
        with open(summary_path, "a", encoding="utf-8") as out:
            out.write(f"\n- {marker}.result=unavailable (empty JSONL after parse)\n")
            out.write(f"- {marker}.parse.base_invalid={base_invalid}\n")
            out.write(f"- {marker}.parse.current_invalid={cur_invalid}\n")
            out.write(f"- {marker}.parse.base_lines={base_lines}\n")
            out.write(f"- {marker}.parse.current_lines={cur_lines}\n")
            out.write(f"- {marker}.parse.health={parse_health}\n")
            if not strict_mode:
                out.write(
                    f"- {marker}.policy=relaxed (COLDSTEP_DIFF_STRICT!=1, unavailable diff does not fail here)\n"
                )
        return 1 if strict_mode else 0

    prev_tr, prev_ot, prev_un = count_fps(base_ev)
    cur_tr, cur_ot, cur_un = count_fps(cur_ev)

    tr_new, tr_gone, tr_chg = multiset_diff(prev_tr, cur_tr)
    ot_new, ot_gone, ot_chg = multiset_diff(prev_ot, cur_ot)
    un_new, un_gone, un_chg = multiset_diff(prev_un, cur_un)

    changed = bool(
        tr_new or tr_gone or tr_chg or ot_new or ot_gone or ot_chg or un_new or un_gone or un_chg
    )

    max_rows = 30
    with open(summary_path, "a", encoding="utf-8") as out:
        out.write("\n#### Traffic shape diff (ignores pid / seq / ts / comm)\n\n")
        out.write(
            "Fingerprints are built from **dst/dport**, **HTTP host/path/method**, **TLS SNI**, "
            "**UDP/TCP policy labels**, and **deny tuples** — not process IDs.\n"
        )

        write_table(
            out,
            "New traffic (present in current, absent in baseline)",
            [(c, k) for c, k in tr_new[:max_rows]],
            ["Current count", "Fingerprint"],
        )
        if len(tr_new) > max_rows:
            out.write(f"\n_Showing first {max_rows} of {len(tr_new)} new traffic fingerprints._\n")

        write_table(
            out,
            "Missing traffic (present in baseline, absent in current)",
            [(c, k) for c, k in tr_gone[:max_rows]],
            ["Baseline count", "Fingerprint"],
        )
        if len(tr_gone) > max_rows:
            out.write(f"\n_Showing first {max_rows} of {len(tr_gone)} missing traffic fingerprints._\n")

        write_table(
            out,
            "Traffic multiplicity changes (same fingerprint, different counts)",
            [(a, b, k) for a, b, k in tr_chg[:max_rows]],
            ["Baseline", "Current", "Fingerprint"],
        )
        if len(tr_chg) > max_rows:
            out.write(
                f"\n_Showing first {max_rows} of {len(tr_chg)} multiplicity changes._\n"
            )

        out.write("\n#### Other telemetry shape diff (PID ignored)\n\n")
        out.write(
            "Exec / fs_event / proc_fork fingerprints drop **pid** / **seq** / **ts**; "
            "paths and comm strings may still vary between runs.\n"
        )

        write_table(
            out,
            "New other fingerprints",
            [(c, k) for c, k in ot_new[:max_rows]],
            ["Current count", "Fingerprint"],
        )
        if len(ot_new) > max_rows:
            out.write(f"\n_Showing first {max_rows} of {len(ot_new)} new other fingerprints._\n")

        write_table(
            out,
            "Missing other fingerprints",
            [(c, k) for c, k in ot_gone[:max_rows]],
            ["Baseline count", "Fingerprint"],
        )
        if len(ot_gone) > max_rows:
            out.write(f"\n_Showing first {max_rows} of {len(ot_gone)} missing other fingerprints._\n")

        write_table(
            out,
            "Other multiplicity changes",
            [(a, b, k) for a, b, k in ot_chg[:max_rows]],
            ["Baseline", "Current", "Fingerprint"],
        )
        if len(ot_chg) > max_rows:
            out.write(
                f"\n_Showing first {max_rows} of {len(ot_chg)} other multiplicity changes._\n"
            )

        out.write("\n#### Unclassified event-type diff\n\n")
        write_table(
            out,
            "New unclassified event types",
            [(c, k) for c, k in un_new[:max_rows]],
            ["Current count", "Event type"],
        )
        write_table(
            out,
            "Missing unclassified event types",
            [(c, k) for c, k in un_gone[:max_rows]],
            ["Baseline count", "Event type"],
        )
        write_table(
            out,
            "Unclassified multiplicity changes",
            [(a, b, k) for a, b, k in un_chg[:max_rows]],
            ["Baseline", "Current", "Event type"],
        )

        out.write("\n")
        parse_health = "degraded" if (base_invalid or cur_invalid) else "ok"
        out.write(f"- {marker}.parse.base_invalid={base_invalid}\n")
        out.write(f"- {marker}.parse.current_invalid={cur_invalid}\n")
        out.write(f"- {marker}.parse.base_lines={base_lines}\n")
        out.write(f"- {marker}.parse.current_lines={cur_lines}\n")
        out.write(f"- {marker}.parse.health={parse_health}\n")
        out.write(f"- {marker}.unclassified.base_total={sum(prev_un.values())}\n")
        out.write(f"- {marker}.unclassified.current_total={sum(cur_un.values())}\n")
        if changed:
            out.write(f"- {marker}.result=changed\n")
            out.write(
                "- **Traffic / telemetry drift:** at least one traffic or other fingerprint differs.\n"
            )
        else:
            out.write(f"- {marker}.result=no-change\n")
            out.write(
                "- **No drift:** traffic and other fingerprints match between runs "
                "(per-type volume table above may still differ).\n"
            )
    if strict_mode and (base_invalid or cur_invalid):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
