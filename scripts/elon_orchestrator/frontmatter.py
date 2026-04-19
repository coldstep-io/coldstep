"""Read and write Markdown files with YAML-lite frontmatter.

Atomic writes: serialize to a sibling temp file, then os.replace() onto target.
This avoids leaving a half-written file if the process dies mid-write.
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

from scripts.elon_orchestrator import yaml_lite

_FENCE = "---"


def read(path: Path) -> tuple[dict, str]:
    """Return (frontmatter_dict, body_text). frontmatter_dict is empty if no frontmatter."""
    text = Path(path).read_text(encoding="utf-8")
    lines = text.splitlines(keepends=True)
    if not lines or lines[0].rstrip("\r\n") != _FENCE:
        return {}, text
    end_idx = None
    for i in range(1, len(lines)):
        if lines[i].rstrip("\r\n") == _FENCE:
            end_idx = i
            break
    if end_idx is None:
        return {}, text
    fm_text = "".join(lines[1:end_idx])
    body = "".join(lines[end_idx + 1 :])
    return yaml_lite.parse(fm_text), body


def write(path: Path, frontmatter: dict, body: str) -> None:
    """Atomically write a Markdown file with YAML-lite frontmatter then body."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fm_text = yaml_lite.dump(frontmatter) if frontmatter else ""
    if fm_text:
        full = f"{_FENCE}\n{fm_text}{_FENCE}\n{body}"
    else:
        full = body
    fd, tmp_path = tempfile.mkstemp(dir=str(target.parent), prefix=".elon-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(full)
        os.replace(tmp_path, target)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
