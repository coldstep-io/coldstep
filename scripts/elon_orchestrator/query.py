"""Query helpers across the brain. All three public functions take vault_root: Path
and return list[Path] of absolute, sorted-by-natural-order results.
"""
from __future__ import annotations

import re
from pathlib import Path

from scripts.elon_orchestrator import frontmatter

_BUCKETS = ("records", "raw", "wiki", "reports")


def _walk_md(vault_root: Path):
    for bucket in _BUCKETS:
        bucket_dir = Path(vault_root) / bucket
        if not bucket_dir.is_dir():
            continue
        for path in sorted(bucket_dir.rglob("*.md")):
            yield path


def find_by_tag(tag: str, vault_root: Path) -> list[Path]:
    """Return all .md files in the vault whose frontmatter `tags:` includes tag,
    OR whose body contains the inline `#<tag>` hashtag (with word boundaries).
    """
    inline_re = re.compile(rf"(?<![\w-])#{re.escape(tag)}(?![\w-])")
    hits: list[Path] = []
    for path in _walk_md(vault_root):
        meta, body = frontmatter.read(path)
        meta_tags = meta.get("tags") or []
        if isinstance(meta_tags, list) and tag in meta_tags:
            hits.append(path)
            continue
        if inline_re.search(body):
            hits.append(path)
    return hits
