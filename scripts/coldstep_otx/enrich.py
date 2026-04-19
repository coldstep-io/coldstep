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
- Per-indicator `::warning::` / `::notice::` lines on stderr are **off** by default
  (set `COLDSTEP_OTX_VERBOSE_ANNOTATIONS=1` to opt in). Full OTX rows live in
  Tier-2 HTML. Low-confidence malicious is always silent.
- Verdict precedence for sort and join: malicious > unidentified > clean.

Env vars when run as a script:
- COLDSTEP_REPORT_MODEL_IN     (required) - path to the v2 model to enrich in place
- OTX_API_KEY                  (optional) - if empty, the step is skipped cleanly
- COLDSTEP_OTX_WALL_BUDGET_MS  (optional, default 30000)
- COLDSTEP_OTX_VERBOSE_ANNOTATIONS  (optional, default 0) - per-indicator stderr annotations
"""
from __future__ import annotations

import datetime as dt
import json
import os
import re
import sys
import tempfile
import time
from pathlib import Path
from typing import Callable, Iterable

from scripts.coldstep_otx.allowlist import is_allowlisted
from scripts.coldstep_otx.client import InvalidAPIKey, OTXClient, OTXError, RateLimited
from scripts.coldstep_otx.confidence import _filtered_pulses_with_audit, tier
from scripts.coldstep_otx.pulse_severity import pulse_signal_severity
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


def _otx_stderr_annotations_enabled() -> bool:
    """Per-indicator workflow annotations are noisy; Tier-2 HTML holds full detail.

    Opt in with ``COLDSTEP_OTX_VERBOSE_ANNOTATIONS=1`` (local debugging).
    """
    raw = os.environ.get("COLDSTEP_OTX_VERBOSE_ANNOTATIONS", "0").strip().lower()
    return raw in ("1", "true", "yes", "on")


def _emit_annotation(
    stderr,
    indicator: str,
    evidence: list[dict],
    *,
    confidence: str,
    pulse_severity: str,
    pulse_count: int,
) -> None:
    """Emit ::warning:: for high, ::notice:: for medium; silent for low."""
    if not _otx_stderr_annotations_enabled():
        return
    if confidence == "low":
        return
    titles = ", ".join(_wf_data(e.get("pulse_name") or e.get("pulse_id") or "?") for e in evidence[:2])
    families = sorted({_wf_data(fam) for e in evidence for fam in (e.get("malware_families") or []) if fam})
    fam_part = f" families={','.join(families)}" if families else ""
    level = "warning" if confidence == "high" else "notice"
    msg = (
        f"::{level} title=OTX {_wf_data(confidence)} confidence malicious::{_wf_data(indicator)} matched "
        f"{len(evidence)} pulse(s){fam_part} ({titles})"
    )
    msg += (
        f" pulse_signal={_wf_data(pulse_severity)} ({pulse_count} filtered pulse(s))"
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
        "allowlist_buckets": {"loopback": 0, "rfc1918": 0, "link-local": 0},
        "filter_drops": 0,
        "indicators": [],
        "summary": {
            "malicious": 0,
            "clean": 0,
            "unidentified": 0,
            "total": 0,
            "by_confidence": {"high": 0, "medium": 0, "low": 0, "null": 0},
            "by_pulse_severity": {"Low": 0, "Medium": 0, "High": 0, "Critical": 0},
        },
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
    _dns = model.get("dns_lookups")
    dns_lookups: dict[str, str] = _dns if isinstance(_dns, dict) else {}

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
    allowlist_buckets: dict[str, int] = {
        "loopback": 0,
        "rfc1918": 0,
        "link-local": 0,
    }
    partial = False
    filter_drops_total = 0
    for indicator, ind_type in pairs:
        # Allowlist runs first so loopback/RFC-reserved space never hits the
        # network or the wall-clock budget. Indicator is still recorded - we
        # never silently drop an observed action.
        reason = is_allowlisted(indicator)
        if reason is not None:
            allowlist_buckets[reason] = allowlist_buckets.get(reason, 0) + 1
            indicators_out.append({
                "indicator": indicator,
                "type": ind_type,
                "verdict": "clean",
                "source": "allowlist",
                "reason": reason,
                "confidence": None,
                "confidence_reasons": [],
                "pulse_severity": "Informational",
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
            indicators_out.append({
                "indicator": indicator,
                "type": ind_type,
                "verdict": "unidentified",
                "note": "rate-limited",
                "confidence": None,
                "confidence_reasons": [],
                "pulse_severity": "Informational",
            })
            continue
        except OTXError as e:
            indicators_out.append({
                "indicator": indicator,
                "type": ind_type,
                "verdict": "unidentified",
                "note": f"otx error: {e}",
                "confidence": None,
                "confidence_reasons": [],
                "pulse_severity": "Informational",
            })
            continue
        except Exception as e:
            # Final safety net: any non-OTXError escaping the client (a regression
            # in our own code, a stdlib bug, an unexpected runtime error, etc.)
            # must NOT crash the detect job. Tag the indicator and move on.
            # Regressed in CI run 24618444911 where a TimeoutError escaped a
            # buggy client and killed the step.
            indicators_out.append({
                "indicator": indicator,
                "type": ind_type,
                "verdict": "unidentified",
                "note": f"unexpected error: {type(e).__name__}: {e}",
                "confidence": None,
                "confidence_reasons": [],
                "pulse_severity": "Informational",
            })
            continue
        verdict, evidence = classify(general)
        row: dict = {"indicator": indicator, "type": ind_type, "verdict": verdict}
        if verdict == "malicious":
            kept, dropped = _filtered_pulses_with_audit(general)
            pulse_info = (general or {}).get("pulse_info") or {}
            raw_pulses = pulse_info.get("pulses") or []
            pulse_count_unfiltered = pulse_info.get("count", len(raw_pulses))
            conf, conf_reasons = tier(general, hostname=dns_lookups.get(indicator))
            row["confidence"] = conf
            row["confidence_reasons"] = conf_reasons
            row["pulse_count"] = len(kept)
            row["pulse_count_unfiltered"] = pulse_count_unfiltered
            row["filtered_pulses"] = dropped
            filter_drops_total += len(dropped)
            row["evidence"] = evidence
            ps = pulse_signal_severity(
                verdict="malicious",
                filtered_pulse_count=len(kept),
            )
            row["pulse_severity"] = ps
            _emit_annotation(
                stderr,
                indicator,
                evidence,
                confidence=conf,
                pulse_severity=ps,
                pulse_count=len(kept),
            )
        elif verdict == "clean":
            row["confidence"] = None
            row["confidence_reasons"] = []
            row["pulse_severity"] = "Informational"
            validation = (general or {}).get("validation") or []
            row["validation"] = [
                (v.get("name") if isinstance(v, dict) else str(v)) for v in validation
            ]
        else:
            row["confidence"] = None
            row["confidence_reasons"] = []
            row["pulse_severity"] = "Informational"
        indicators_out.append(row)

    indicators_out.sort(key=lambda r: (VERDICT_ORDER.get(r["verdict"], 99), r["indicator"]))
    summary = {"malicious": 0, "clean": 0, "unidentified": 0}
    for row in indicators_out:
        summary[row["verdict"]] = summary.get(row["verdict"], 0) + 1
    summary["total"] = sum(summary.values())
    by_confidence = {"high": 0, "medium": 0, "low": 0, "null": 0}
    for row in indicators_out:
        ck = row.get("confidence") or "null"
        by_confidence[ck] = by_confidence.get(ck, 0) + 1
    summary["by_confidence"] = by_confidence
    by_pulse_severity = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
    for row in indicators_out:
        ps = row.get("pulse_severity")
        if ps in by_pulse_severity:
            by_pulse_severity[ps] += 1
    summary["by_pulse_severity"] = by_pulse_severity

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
        "allowlist_buckets": allowlist_buckets,
        "filter_drops": filter_drops_total,
        "indicators": indicators_out,
        "summary": summary,
    }
    Path(model_path).write_text(json.dumps(model), encoding="utf-8")
    return 0


# Snyk Code (python/PT, CWE-23) treats every os.environ.get(...) value as
# untrusted. main() canonicalises every env-var path through this helper
# before it reaches a Path()/open() sink. Inlined per file because Snyk's
# taint analysis only recognises sanitisers that live in the same module
# as the sink. Mirrors scripts/coldstep_detect_report/build_report_model.py
# so the trusted-root set stays identical (AGENTS.md canonical helper).
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
            model_path = _safe_workspace_path(
                raw_model_path, var_name="COLDSTEP_REPORT_MODEL_IN"
            )
        except ValueError as e:
            print(
                f"::warning title=OTX enrichment refused untrusted path::{_wf_data(e)}",
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
