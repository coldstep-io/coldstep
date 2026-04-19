"""Build the canonical report model consumed by both renderers.

Pure data layer: I/O at the edges, transformations in pure functions so the
renderers and unit tests share a single source of truth.
"""
from __future__ import annotations

import collections
import datetime as dt
import functools
import importlib.util
import json
import os
import sys
from pathlib import Path
from typing import Optional

SCHEMA_VERSION = 1

REQUIRED_CAPABILITIES = (
    ("exec", "Exec tracing"),
    ("tcp", "TCP connect telemetry"),
    ("udp", "UDP sendto telemetry"),
    ("http", "HTTP cleartext telemetry"),
    ("tls", "TLS ClientHello/SNI hint"),
    ("proc_fork", "Process tree (fork)"),
    ("fs_event", "Filesystem events"),
)

EGRESS_TYPES = ("tcp", "udp", "http", "tls")


@functools.lru_cache(maxsize=1)
def _load_diff_module():
    # Lazy-load so a breakage in the sibling diff script does not blow up at import time;
    # the helper is only needed when a baseline is supplied to _diff().
    diff_script = Path(__file__).resolve().parent.parent / "ci_coldstep_jsonl_traffic_diff.py"
    spec = importlib.util.spec_from_file_location("coldstep_diff_internal", diff_script)
    if spec is None or spec.loader is None:
        raise ImportError(f"could not load diff helper module from {diff_script}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


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


def _capability_matrix(events: list[dict]) -> list[dict]:
    seen = collections.Counter(ev.get("type", "") for ev in events)
    matrix = []
    for cap_id, label in REQUIRED_CAPABILITIES:
        count = seen.get(cap_id, 0)
        matrix.append({
            "id": cap_id,
            "label": label,
            "status": "pass" if count > 0 else "fail",
            "evidence_count": count,
        })
    return matrix


def _events_by_type(events: list[dict]) -> list[dict]:
    seen = collections.Counter(
        ev.get("type", "<missing>") for ev in events if ev.get("type") != "meta"
    )
    return [{"type": t, "count": n} for t, n in sorted(seen.items(), key=lambda x: (-x[1], x[0]))]


def _timeline(events: list[dict], bucket_seconds: int = 1) -> list[dict]:
    buckets: dict[tuple[str, str], int] = collections.defaultdict(int)
    for ev in events:
        ts = ev.get("ts")
        t = ev.get("type", "<missing>")
        if not ts:
            continue
        try:
            stamp = dt.datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except ValueError:
            continue
        epoch = int(stamp.timestamp())
        bucket = epoch - (epoch % bucket_seconds)
        bucket_iso = dt.datetime.fromtimestamp(bucket, tz=dt.timezone.utc).isoformat().replace("+00:00", "Z")
        buckets[(bucket_iso, t)] += 1
    return [{"bucket": b, "type": t, "count": n} for (b, t), n in sorted(buckets.items())]


def _egress_sankey(events: list[dict]) -> list[dict]:
    edges: dict[tuple[str, str], int] = collections.defaultdict(int)
    for ev in events:
        if ev.get("type") not in EGRESS_TYPES:
            continue
        host = (
            ev.get("fqdn")
            or ev.get("host")
            or ev.get("sni")
            or ev.get("dst")
            or "unknown"
        )
        # Preserve empty-string policy verbatim (matches traffic_fingerprint upstream so
        # the sankey and diff sections never disagree on the same event).
        policy = ev.get("policy", "")
        edges[(str(host), str(policy))] += 1
    return [{"source": s, "target": t, "value": v} for (s, t), v in sorted(edges.items())]


def _diff(current: list[dict], baseline: Optional[list[dict]]) -> dict:
    if baseline is None:
        return {"status": "unavailable", "reason": "no_baseline_provided",
                "traffic_new": [], "traffic_gone": [], "traffic_changed": []}
    diff_mod = _load_diff_module()
    cur_tr, _, _ = diff_mod.count_fps(current)
    base_tr, _, _ = diff_mod.count_fps(baseline)
    new, gone, chg = diff_mod.multiset_diff(base_tr, cur_tr)
    return {
        "status": "ok",
        "traffic_new": [{"count": c, "fingerprint": k} for c, k in new],
        "traffic_gone": [{"count": c, "fingerprint": k} for c, k in gone],
        "traffic_changed": [{"baseline": a, "current": b, "fingerprint": k} for a, b, k in chg],
    }


def build(
    current_jsonl: str,
    baseline_jsonl: Optional[str],
    *,
    now: Optional[dt.datetime] = None,
) -> dict:
    when = now if now is not None else dt.datetime.now(tz=dt.timezone.utc)
    current = _load_jsonl(current_jsonl)
    baseline = _load_jsonl(baseline_jsonl) if baseline_jsonl else None
    meta = next((ev for ev in current if ev.get("type") == "meta"), {})
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": when.isoformat().replace("+00:00", "Z"),
        "run": {
            "run_id": meta.get("run_id") or os.environ.get("GITHUB_RUN_ID", ""),
            # GITHUB_WORKFLOW_REF format is "{owner}/{repo}/.github/workflows/{file}@{ref}"
            "workflow_file": os.environ.get("GITHUB_WORKFLOW_REF", "").split("@")[0].rsplit("/", 1)[-1],
            "branch": os.environ.get("GITHUB_HEAD_REF") or os.environ.get("GITHUB_REF_NAME", ""),
            "runner_label": os.environ.get("NS_RUNNER_LABEL", ""),
        },
        "capability_matrix": _capability_matrix(current),
        "events_by_type": _events_by_type(current),
        "timeline": _timeline(current),
        "egress_sankey": _egress_sankey(current),
        "diff": _diff(current, baseline),
    }


def main() -> int:
    cur = os.environ.get("COLDSTEP_REPORT_CURRENT_JSONL", "")
    base = os.environ.get("COLDSTEP_REPORT_BASELINE_JSONL", "") or None
    out = os.environ.get("COLDSTEP_REPORT_MODEL_OUT", "")
    if not cur or not out:
        missing = [
            name for name, val in
            (("COLDSTEP_REPORT_CURRENT_JSONL", cur), ("COLDSTEP_REPORT_MODEL_OUT", out))
            if not val
        ]
        print(f"build_report_model: missing required env vars: {', '.join(missing)}", file=sys.stderr)
        return 1
    model = build(current_jsonl=cur, baseline_jsonl=base)
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    Path(out).write_text(json.dumps(model, indent=2, sort_keys=False), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
