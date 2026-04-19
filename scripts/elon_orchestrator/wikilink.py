"""Wikilink resolution + closest-match suggestions for Obsidian-style links.

resolve("[[wiki/foo]]" or "wiki/foo" or "wiki/foo|alias", vault_root) -> Path | None
closest_wikilink_match("wiki/fo", vault_root, n=3) -> ["wiki/foo", "wiki/food"]
"""
from __future__ import annotations

import difflib
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


def closest_wikilink_match(target: str, vault_root: Path, n: int = 3) -> list[str]:
    """Suggest up to n closest wikilink targets in the same bucket.

    Returns canonical "<bucket>/<slug>" strings (no .md extension, no brackets).
    Returns an empty list when there is no remotely-close match.
    """
    rel = _normalize(target)
    if "/" not in rel:
        return []
    bucket, slug = rel.split("/", 1)
    if bucket not in _KNOWN_BUCKETS:
        return []
    if slug.endswith(".md"):
        slug = slug[:-3]
    bucket_dir = Path(vault_root) / bucket
    if not bucket_dir.is_dir():
        return []
    candidates = [p.stem for p in bucket_dir.glob("*.md")]
    matches = difflib.get_close_matches(slug, candidates, n=n, cutoff=0.5)
    return [f"{bucket}/{m}" for m in matches]
