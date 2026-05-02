#!/usr/bin/env python3
"""
Guardrail: consumer-facing coldstep-io/coldstep pin matches the tag we publish.

Bump MARKETPLACE_COLDSTEP_TAG with each release (see RELEASE_PROCESS.md).
"""
from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]

# Must match the Git tag published on GitHub Releases for coldstep-io/coldstep.
MARKETPLACE_COLDSTEP_TAG = "v0.2.1"

PIN_PREFIX = "coldstep-io/coldstep@"
EXPECTED = f"{PIN_PREFIX}{MARKETPLACE_COLDSTEP_TAG}"

# Files that must advertise the recommended consumer pin (substring match).
PINNED_FILES = (
    ROOT / "README.md",
    ROOT / "QUICK_START.md",
    ROOT / "CONTRIBUTING.md",
    ROOT / "website" / "index.html",
)


def _scan_wrong_pins(text: str) -> list[str]:
    bad: list[str] = []
    for line in text.splitlines():
        if "not usable" in line.lower() or "do not use" in line.lower():
            continue
        found = re.findall(re.escape(PIN_PREFIX) + r"(v[0-9][^\s`'\"<>]*)", line)
        bad.extend(x for x in found if x != MARKETPLACE_COLDSTEP_TAG)
    return sorted(set(bad))


def main() -> int:
    exit_code = 0
    for path in PINNED_FILES:
        if not path.is_file():
            print(f"skip missing {path.relative_to(ROOT)}", file=sys.stderr)
            continue
        text = path.read_text(encoding="utf-8")
        wrong = _scan_wrong_pins(text)
        if wrong:
            print(
                f"{path.relative_to(ROOT)}: expected only {EXPECTED}, also saw {wrong}",
                file=sys.stderr,
            )
            exit_code = 1
        elif EXPECTED not in text and PIN_PREFIX in text:
            print(
                f"{path.relative_to(ROOT)}: uses coldstep-io/coldstep@ but missing {EXPECTED}",
                file=sys.stderr,
            )
            exit_code = 1

    for rel in (
        ".github/workflows/coldstep-demo.yml",
        ".github/workflows/coldstep-redteam-ebpf.yml",
    ):
        wf = ROOT / rel
        if not wf.is_file():
            continue
        text = wf.read_text(encoding="utf-8")
        want = f"COLDSTEP_AGENT_VERSION: {MARKETPLACE_COLDSTEP_TAG}"
        if want not in text:
            print(
                f"{wf.relative_to(ROOT)}: missing {want}",
                file=sys.stderr,
            )
            exit_code = 1

    if exit_code == 0:
        print(f"OK MARKETPLACE_COLDSTEP_TAG={MARKETPLACE_COLDSTEP_TAG}")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
