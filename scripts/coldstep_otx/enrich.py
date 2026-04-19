"""OTX enrichment orchestrator.

Reads a coldstep report-model.json (schema v2 with `otx: null` placeholder),
walks every indicator-bearing slot (egress sankey + diff buckets), classifies
each unique indicator via OTX, and writes the enriched model back in place.

Constraints:
- Wall-clock budget (default 30s). Budget exhaustion -> partial_results: true,
  remaining indicators skipped, exit code 0.
- Missing/empty OTX_API_KEY -> skipped: true, exit code 0.
- 403 from OTX -> skipped: true, exit code 0 (the secret is wrong but we don't
  fail the detect job over a third-party auth issue).
- Each malicious indicator -> a `::warning::` workflow command on stderr.
- Verdict precedence for sort and join: malicious > unidentified > clean.

Env vars when run as a script:
- COLDSTEP_REPORT_MODEL_IN     (required) - path to the v2 model to enrich in place
- OTX_API_KEY                  (optional) - if empty, the step is skipped cleanly
- COLDSTEP_OTX_WALL_BUDGET_MS  (optional, default 30000)
"""
from __future__ import annotations

import datetime as dt
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Callable, Iterable

from scripts.coldstep_otx.allowlist import is_allowlisted
from scripts.coldstep_otx.client import InvalidAPIKey, OTXClient, OTXError, RateLimited
from scripts.coldstep_otx.verdict import classify

VERDICT_ORDER = {"malicious": 0, "unidentified": 1, "clean": 2}


def _is_ipv4(s: str) -> bool:
    parts = s.split(".")
    if len(parts) != 4:
        return False
    for p in parts:
        if not p.isdigit():
            return False
        n = int(p)
        if n < 0 or n > 255:
            return False
    return True


def _gather_indicators(model: dict) -> list[tuple[str, str]]:
    """Return deduped (indicator, indicator_type) pairs in stable order."""
    seen: dict[str, str] = {}  # indicator -> type
    def add_iter(items: Iterable[str]) -> None:
        for ind in items:
            if not ind or ind in seen:
                continue
            seen[ind] = "IPv4" if _is_ipv4(ind) else "hostname"
    for edge in (model.get("egress_sankey") or []):
        add_iter(edge.get("indicators") or [])
    for bucket in ("traffic_new", "traffic_gone", "traffic_changed"):
        for entry in (model.get("diff") or {}).get(bucket, []):
            add_iter(entry.get("indicators") or [])
    # Stable sort: IPv4 first, then hostnames; within each, alphabetical.
    return sorted(seen.items(), key=lambda kv: (kv[1] != "IPv4", kv[0]))


def _wf_data(s: object) -> str:
    """Encode user-derived strings for GitHub Actions workflow commands.

    Workflow commands are line-oriented; an OTX pulse name containing a literal
    newline could inject a second `::error::` annotation downstream. Encode `%`,
    `\\r`, `\\n` per
    https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions
    """
    return str(s).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _emit_warning(stderr, indicator: str, evidence: list[dict]) -> None:
    titles = ", ".join(_wf_data(e.get("pulse_name") or e.get("pulse_id") or "?") for e in evidence[:2])
    families = sorted({_wf_data(fam) for e in evidence for fam in (e.get("malware_families") or []) if fam})
    fam_part = f" families={','.join(families)}" if families else ""
    msg = (
        f"::warning title=OTX malicious indicator::{_wf_data(indicator)} matched "
        f"{len(evidence)} pulse(s){fam_part} ({titles})"
    )
    print(msg, file=stderr)


def _set_skipped(model: dict, reason: str, *, queried_at: str) -> None:
    model["otx"] = {
        "skipped": True,
        "skipped_reason": reason,
        "queried_at": queried_at,
        "wall_ms": 0,
        "wall_budget_ms": 0,
        "partial_results": False,
        "api_calls": 0,
        "rate_limited": 0,
        "allowlisted": 0,
        "indicators": [],
        "summary": {"malicious": 0, "clean": 0, "unidentified": 0, "total": 0},
    }


def run(
    *,
    model_path: str,
    api_key: str,
    client_factory: Callable[[str], object],
    stderr,
    now_monotonic: Callable[[], float],
    wall_budget_ms: int,
) -> int:
    """Execute one enrichment pass. Always returns 0 (never fails the detect job)."""
    model = json.loads(Path(model_path).read_text(encoding="utf-8"))
    queried_at = dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")

    if not api_key:
        _set_skipped(model, "no api key", queried_at=queried_at)
        Path(model_path).write_text(json.dumps(model), encoding="utf-8")
        return 0

    pairs = _gather_indicators(model)
    if not pairs:
        _set_skipped(model, "no indicators in model", queried_at=queried_at)
        Path(model_path).write_text(json.dumps(model), encoding="utf-8")
        return 0

    try:
        client = client_factory(api_key)
    except InvalidAPIKey:
        _set_skipped(model, "403 invalid api key", queried_at=queried_at)
        Path(model_path).write_text(json.dumps(model), encoding="utf-8")
        return 0

    start = now_monotonic()
    budget_s = wall_budget_ms / 1000.0
    indicators_out: list[dict] = []
    api_calls = 0
    rate_limited = 0
    allowlisted = 0
    partial = False
    for indicator, ind_type in pairs:
        # Allowlist runs first so loopback/RFC-reserved space never hits the
        # network or the wall-clock budget. Indicator is still recorded - we
        # never silently drop an observed action.
        reason = is_allowlisted(indicator)
        if reason is not None:
            indicators_out.append({
                "indicator": indicator,
                "type": ind_type,
                "verdict": "clean",
                "source": "allowlist",
                "reason": reason,
            })
            allowlisted += 1
            continue
        if (now_monotonic() - start) >= budget_s:
            partial = True
            break
        try:
            general = client.get_general(ind_type, indicator)
            api_calls += 1
        except InvalidAPIKey:
            _set_skipped(model, "403 invalid api key", queried_at=queried_at)
            Path(model_path).write_text(json.dumps(model), encoding="utf-8")
            return 0
        except RateLimited:
            rate_limited += 1
            indicators_out.append({"indicator": indicator, "type": ind_type,
                                   "verdict": "unidentified", "note": "rate-limited"})
            continue
        except OTXError as e:
            indicators_out.append({"indicator": indicator, "type": ind_type,
                                   "verdict": "unidentified", "note": f"otx error: {e}"})
            continue
        except Exception as e:
            # Final safety net: any non-OTXError escaping the client (a regression
            # in our own code, a stdlib bug, an unexpected runtime error, etc.)
            # must NOT crash the detect job. Tag the indicator and move on.
            # Regressed in CI run 24618444911 where a TimeoutError escaped a
            # buggy client and killed the step.
            indicators_out.append({"indicator": indicator, "type": ind_type,
                                   "verdict": "unidentified",
                                   "note": f"unexpected error: {type(e).__name__}: {e}"})
            continue
        verdict, evidence = classify(general)
        row: dict = {"indicator": indicator, "type": ind_type, "verdict": verdict}
        if verdict == "malicious":
            row["pulse_count"] = (general or {}).get("pulse_info", {}).get("count", len(evidence))
            row["evidence"] = evidence
            _emit_warning(stderr, indicator, evidence)
        elif verdict == "clean":
            validation = (general or {}).get("validation") or []
            row["validation"] = [
                (v.get("name") if isinstance(v, dict) else str(v)) for v in validation
            ]
        indicators_out.append(row)

    indicators_out.sort(key=lambda r: (VERDICT_ORDER.get(r["verdict"], 99), r["indicator"]))
    summary = {"malicious": 0, "clean": 0, "unidentified": 0}
    for row in indicators_out:
        summary[row["verdict"]] = summary.get(row["verdict"], 0) + 1
    summary["total"] = sum(summary.values())

    wall_ms = int((now_monotonic() - start) * 1000)
    model["otx"] = {
        "skipped": False,
        "skipped_reason": None,
        "queried_at": queried_at,
        "wall_ms": wall_ms,
        "wall_budget_ms": wall_budget_ms,
        "partial_results": partial,
        "api_calls": api_calls,
        "rate_limited": rate_limited,
        "allowlisted": allowlisted,
        "indicators": indicators_out,
        "summary": summary,
    }
    Path(model_path).write_text(json.dumps(model), encoding="utf-8")
    return 0


_SAFE_PATH_RE = re.compile(r"^[A-Za-z0-9_./\\:-]+\.json$")


def _safe_model_path(raw: str) -> str:
    # COLDSTEP_REPORT_MODEL_IN is supplied by the workflow, but Snyk Code
    # (python/PT, CWE-23) treats env input as untrusted - and rightly so: a
    # bad value would let an attacker who can flip the env force this script
    # to overwrite an arbitrary JSON file on the runner. Defence is two-stage:
    #   1. Regex allowlist rejects shell metachars, NULs, newlines, ...
    #   2. realpath()+commonpath() containment pins the resolved file inside
    #      GITHUB_WORKSPACE (or cwd outside CI), so `..` traversal is fatal.
    if not _SAFE_PATH_RE.match(raw):
        raise ValueError("disallowed characters in model path")
    root = os.path.realpath(os.environ.get("GITHUB_WORKSPACE") or os.getcwd())
    resolved = os.path.realpath(raw)
    if os.path.commonpath([resolved, root]) != root:
        raise ValueError(f"{resolved!r} is not under {root!r}")
    return resolved


def main() -> int:
    # Final safety net for the always-exit-0 contract: anything that escapes the
    # body (corrupt model JSON, FS errors during read/write, OS-level surprises)
    # surfaces as a workflow `::warning::` and we still exit 0. The detect job
    # never fails on a third-party / I/O issue.
    try:
        raw_model_path = os.environ.get("COLDSTEP_REPORT_MODEL_IN", "")
        if not raw_model_path:
            print("enrich: missing required env var COLDSTEP_REPORT_MODEL_IN", file=sys.stderr)
            return 0
        try:
            model_path = _safe_model_path(raw_model_path)
        except ValueError as e:
            print(
                f"enrich: refusing COLDSTEP_REPORT_MODEL_IN outside workspace: {_wf_data(e)}",
                file=sys.stderr,
            )
            return 0
        api_key = os.environ.get("OTX_API_KEY", "")
        try:
            wall = int(os.environ.get("COLDSTEP_OTX_WALL_BUDGET_MS", "30000"))
        except ValueError:
            wall = 30000
        return run(
            model_path=model_path,
            api_key=api_key,
            client_factory=lambda k: OTXClient(api_key=k),
            stderr=sys.stderr,
            now_monotonic=time.monotonic,
            wall_budget_ms=wall,
        )
    except Exception as e:
        print(
            f"::warning title=OTX enrichment crashed::{_wf_data(type(e).__name__)}: {_wf_data(e)}",
            file=sys.stderr,
        )
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
