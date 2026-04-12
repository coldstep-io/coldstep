#!/usr/bin/env python3
"""
Append a GitHub Actions job-summary section comparing two Coldstep JSONL files.

Traffic fingerprints intentionally omit pid / tgid / thread_id / comm / seq / ts so
consecutive runs can be compared on egress shape (TCP/UDP/HTTP/TLS/deny).
"""

from __future__ import annotations

import collections
import json
import os
import sys


def load_events(path: str) -> list[dict]:
    out: list[dict] = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except OSError:
        return []
    return out


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
        path = ev.get("path") or ""
        if len(path) > 120:
            path = path[:120] + "\u2026"
        return (
            "traffic » http » "
            f"{ev.get('dst', '')} » {ev.get('dport', '')} » "
            f"{(ev.get('host') or '')} » {ev.get('method', '')} » {path} » {ev.get('policy', '')}"
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
        return f"other » exec » {(ev.get('exe') or '')} » {(ev.get('comm') or '')}"
    if t == "fs_event":
        return f"other » fs_event » {ev.get('op', '')} » {(ev.get('path') or '')}"
    if t == "proc_fork":
        return (
            "other » proc_fork » "
            f"{(ev.get('parent_comm') or '')} » {(ev.get('child_comm') or '')}"
        )
    return None


def count_fps(events: list[dict]) -> tuple[collections.Counter[str], collections.Counter[str]]:
    traffic: collections.Counter[str] = collections.Counter()
    other: collections.Counter[str] = collections.Counter()
    for ev in events:
        fp = traffic_fingerprint(ev)
        if fp is not None:
            traffic[fp] += 1
            continue
        fp2 = other_fingerprint(ev)
        if fp2 is not None:
            other[fp2] += 1
    return traffic, other


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

    if not summary_path or not base_path or not cur_path:
        return 1

    base_ev = load_events(base_path)
    cur_ev = load_events(cur_path)
    if not base_ev or not cur_ev:
        with open(summary_path, "a", encoding="utf-8") as out:
            out.write(f"\n- {marker}.result=unavailable (empty JSONL after parse)\n")
        return 0

    prev_tr, prev_ot = count_fps(base_ev)
    cur_tr, cur_ot = count_fps(cur_ev)

    tr_new, tr_gone, tr_chg = multiset_diff(prev_tr, cur_tr)
    ot_new, ot_gone, ot_chg = multiset_diff(prev_ot, cur_ot)

    changed = bool(
        tr_new or tr_gone or tr_chg or ot_new or ot_gone or ot_chg
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

        out.write("\n")
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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
