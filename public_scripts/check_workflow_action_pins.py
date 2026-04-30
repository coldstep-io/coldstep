#!/usr/bin/env python3
"""Guardrail for GitHub Actions workflow pins (D-SR-02 / Task 9).

- Rejects mutable action refs (@main, @master, etc.) on third-party uses: lines.
- Requires the marketplace smoke workflow to pin coldstep-io/coldstep at the
  canonical release tag (keep in sync with README / QUICK_START / AGENTS.md).

Run from repository root: python3 public_scripts/check_workflow_action_pins.py
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# Bump when publishing a new consumer-facing tag (same as README marketplace pin).
MARKETPLACE_COLDSTEP_TAG = "v0.2.0"

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"

USES_LINE = re.compile(r"^\s*(?:-\s*)?uses:\s*(.+?)\s*(?:#.*)?$")

# workflow_call / composite / local
_SKIP_PREFIXES = ("./", "${{")

BLOCKED_REFS = frozenset(
    {
        "main",
        "master",
        "HEAD",
        "dev",
        "develop",
        "latest",
        "nightly",
    }
)


def _parse_use_payload(raw: str) -> tuple[str | None, str | None]:
    """Return (left_of_at, ref) for owner/.../path@ref, or (None, None) to skip."""
    s = raw.strip().strip("'\"")
    if not s or s.startswith(_SKIP_PREFIXES):
        return None, None
    if s.startswith("docker://"):
        return None, None
    if "@" not in s:
        return None, None
    left, ref = s.rsplit("@", 1)
    if "/" not in left:
        return None, None
    ref = ref.strip()
    if not ref:
        return None, None
    return left, ref


def check_file(path: Path) -> list[str]:
    errors: list[str] = []
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as e:
        return [f"{path}: read error: {e}"]
    for i, line in enumerate(text.splitlines(), start=1):
        m = USES_LINE.match(line)
        if not m:
            continue
        payload = m.group(1).strip()
        left, ref = _parse_use_payload(payload)
        if ref is None or left is None:
            continue
        low = ref.lower()
        if low in BLOCKED_REFS:
            errors.append(f"{path}:{i}: forbidden mutable ref @{ref} in uses: {payload!r}")
        if left == "coldstep-io/coldstep" and ref != MARKETPLACE_COLDSTEP_TAG:
            errors.append(
                f"{path}:{i}: coldstep-io/coldstep must pin @{MARKETPLACE_COLDSTEP_TAG} "
                f"(got @{ref}); update public_scripts/check_workflow_action_pins.py + docs together"
            )
    return errors


def main() -> int:
    if not WORKFLOWS.is_dir():
        print(f"expected {WORKFLOWS}", file=sys.stderr)
        return 2
    all_errs: list[str] = []
    for path in sorted(WORKFLOWS.glob("*.yml")) + sorted(WORKFLOWS.glob("*.yaml")):
        all_errs.extend(check_file(path))
    if all_errs:
        for e in all_errs:
            print(e, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
