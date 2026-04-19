"""Reverse-DNS enrichment orchestrator.

Reads a coldstep report-model.json, gathers every IPv4 indicator from the
egress sankey + diff buckets, runs a best-effort PTR batch via the rdns
resolver, and writes `model.dns_lookups: {ip: hostname}` back in place.

Contract mirrors the OTX enricher:
- Always exits 0 (third-party / I/O issues never fail the detect job).
- Schema-additive (only adds the optional top-level `dns_lookups` map).
- Wall-clock budget (default 5s) caps total work.

Env vars:
- COLDSTEP_REPORT_MODEL_IN     (required) - path to the v2 model
- COLDSTEP_RDNS_WALL_BUDGET_MS (optional, default 5000)
"""
from __future__ import annotations

import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Iterable, Optional

from scripts.coldstep_dns.rdns import Resolver, _default_resolver, lookup_batch


def _gather_ipv4_indicators(model: dict) -> list[str]:
    """Walk every indicator-bearing slot and return a deduped list."""
    seen: set[str] = set()
    out: list[str] = []
    def add_iter(items: Iterable[str]) -> None:
        for ind in items:
            if not ind or ind in seen:
                continue
            seen.add(ind)
            out.append(ind)
    for edge in (model.get("egress_sankey") or []):
        add_iter(edge.get("indicators") or [])
    for bucket in ("traffic_new", "traffic_gone", "traffic_changed"):
        for entry in (model.get("diff") or {}).get(bucket, []):
            add_iter(entry.get("indicators") or [])
    return out


def run(
    *,
    model_path: str,
    resolver: Optional[Resolver] = None,
    wall_budget_s: float = 5.0,
    stderr,
) -> int:
    """Always returns 0. Failures surface as workflow warnings, not errors."""
    model = json.loads(Path(model_path).read_text(encoding="utf-8"))
    indicators = _gather_ipv4_indicators(model)
    lookups = lookup_batch(
        indicators,
        resolver=resolver if resolver is not None else _default_resolver,
        wall_budget_s=wall_budget_s,
    )
    model["dns_lookups"] = lookups
    Path(model_path).write_text(json.dumps(model), encoding="utf-8")
    print(
        f"rdns: resolved {len(lookups)}/{len(indicators)} IPv4 indicator(s)",
        file=stderr,
    )
    return 0


def _wf_data(s: object) -> str:
    """Encode user-derived strings for GitHub Actions workflow commands.

    Workflow commands are line-oriented; a surprise path containing a literal
    newline could inject a second `::warning::` annotation downstream. Encode
    `%`, `\\r`, `\\n` per
    https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions
    """
    return str(s).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


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
    # Mirrors enrich.py's catch-all: every load/parse/write/runtime surprise
    # surfaces as a workflow warning and we still exit 0.
    try:
        raw_model_path = os.environ.get("COLDSTEP_REPORT_MODEL_IN", "")
        if not raw_model_path:
            print("enrich_rdns: missing required env var COLDSTEP_REPORT_MODEL_IN",
                  file=sys.stderr)
            return 0
        try:
            model_path = _safe_workspace_path(
                raw_model_path, var_name="COLDSTEP_REPORT_MODEL_IN"
            )
        except ValueError as e:
            print(
                f"::warning title=rDNS enrichment refused untrusted path::{_wf_data(e)}",
                file=sys.stderr,
            )
            return 0
        try:
            wall_ms = int(os.environ.get("COLDSTEP_RDNS_WALL_BUDGET_MS", "5000"))
        except ValueError:
            wall_ms = 5000
        return run(
            model_path=model_path,
            resolver=None,
            wall_budget_s=wall_ms / 1000.0,
            stderr=sys.stderr,
        )
    except Exception as e:
        print(
            f"::warning title=rDNS enrichment crashed::{type(e).__name__}: {e}",
            file=sys.stderr,
        )
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
