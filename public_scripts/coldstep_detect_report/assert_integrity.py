"""Assert that the capability evaluation verdict is not 'fail'.

Used to enforce anti-blindness gating in CI: if the integrity score is zero
(mandatory events or canaries missing), the job fails.
"""
from __future__ import annotations

import json
import os
import re
import sys
import tempfile
from pathlib import Path


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
    raw_in = os.environ.get("COLDSTEP_REPORT_MODEL_IN", "")
    if not raw_in:
        print("assert_integrity: COLDSTEP_REPORT_MODEL_IN env var missing", file=sys.stderr)
        return 1
    
    try:
        path_in = _safe_workspace_path(raw_in, var_name="COLDSTEP_REPORT_MODEL_IN")
    except ValueError as e:
        print(f"assert_integrity: refusing untrusted path: {e}", file=sys.stderr)
        return 1

    if not Path(path_in).exists():
        print(f"assert_integrity: model file not found: {path_in}", file=sys.stderr)
        return 1

    with open(path_in, "r", encoding="utf-8") as f:
        model = json.load(f)

    eval_res = model.get("capability_eval", {})
    verdict = eval_res.get("verdict", "unknown")
    score = eval_res.get("score", 0)
    
    if verdict == "fail":
        reasons = eval_res.get("integrity", {}).get("reasons", [])
        print("::error title=Coldstep Integrity Failure::Detect-mode integrity check failed (score: %d). Required telemetry was missing." % score)
        for reason in reasons:
            advice = "Verify agent permissions and kernel compatibility."
            if reason == "INTEGRITY_REQUIRED_TYPE_MISSING":
                missing = eval_res.get("integrity", {}).get("details", {}).get("missing_types", [])
                advice = "Required event types missing: %s. Ensure the BPF programs are loaded and not failing." % ", ".join(missing)
            elif reason == "INTEGRITY_CANARY_MISSING":
                advice = "Mandatory security canaries not found. The agent may have been bypassed or the kernel is not triggering the expected hooks."
            
            print("::error::Integrity Failure Reason: %s - %s" % (reason, advice))
        
        print("\n[REMEDIATION] See knowledge/reports/2026-04-28-coldstep-telemetry-integrity-hardening.md for troubleshooting.")
        return 1

    print("Coldstep Integrity Pass: verdict=%s score=%d" % (verdict, score))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
