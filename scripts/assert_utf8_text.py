#!/usr/bin/env python3
"""
Fail if git-tracked text files look UTF-16 (common when Windows editors
save as "Unicode" / UTF-16 LE). Go, TypeScript, and GitHub Actions manifests
must be UTF-8; UTF-16 breaks go/tsc, EditorConfig consumers, and composite action.yml loading on GitHub.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from utf8_repo_text import is_candidate, looks_utf16


def main() -> int:
    out = subprocess.run(
        ["git", "ls-files"],
        check=True,
        capture_output=True,
        text=True,
    )
    paths = [p for p in out.stdout.splitlines() if p]
    bad: list[str] = []
    for rel in paths:
        p = Path(rel)
        if not is_candidate(p):
            continue
        try:
            b = p.read_bytes()
        except OSError:
            continue
        if not b:
            continue
        if looks_utf16(b):
            bad.append(rel)
    if bad:
        print(
            "UTF-16 (or UTF-16-like) encoding detected. Re-save as UTF-8 (no BOM).",
            file=sys.stderr,
        )
        for f in bad:
            print(f"  {f}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
