"""Wikilink resolution + closest-match suggestions for Obsidian-style links.

resolve("[[wiki/foo]]" or "wiki/foo" or "wiki/foo|alias", vault_root) -> Path | None
closest_wikilink_match("wiki/fo", vault_root, n=3) -> ["wiki/foo", "wiki/food"]
"""
from __future__ import annotations

import re
from pathlib import Path

_BRACKET = re.compile(r"^\[\[(.+?)\]\]$")
_KNOWN_BUCKETS = ("records", "raw", "wiki", "reports")


def _normalize(target: str) -> str:
    """Strip [[ ]] brackets and |alias suffix; return the raw bucket/slug path."""
    target = target.strip()
    m = _BRACKET.match(target)
    if m:
        target = m.group(1)
    if "|" in target:
        target = target.split("|", 1)[0]
    return target.strip()


def resolve(target: str, vault_root: Path) -> Path | None:
    """Resolve a wikilink to an absolute Path in the vault, or None if missing/invalid."""
    rel = _normalize(target)
    if "/" not in rel:
        return None
    bucket = rel.split("/", 1)[0]
    if bucket not in _KNOWN_BUCKETS:
        return None
    if not rel.endswith(".md"):
        rel = f"{rel}.md"
    candidate = Path(vault_root) / rel
    return candidate if candidate.is_file() else None
