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


def find_by_wikilink_target(target: str, vault_root: Path) -> list[Path]:
    """Return all files whose body contains a wikilink pointing at `target`.

    Matches `[[<target>]]` and `[[<target>|alias]]` exactly. Does NOT match
    `[[<target>-suffix]]` or `[[<other>/<target>]]`.
    """
    pattern = re.compile(
        r"\[\[" + re.escape(target) + r"(?:\|[^\]]+)?\]\]"
    )
    hits: list[Path] = []
    for path in _walk_md(vault_root):
        body = path.read_text(encoding="utf-8")
        if pattern.search(body):
            hits.append(path)
    return hits


_LINK_RE = re.compile(r"\[\[(records|raw)/([^\]|]+?)(?:\|[^\]]+)?\]\]")


def find_records_for_wiki(hub_path: Path, vault_root: Path) -> list[Path]:
    """Walk one hop from a wiki hub: collect every records/* file linked from
    the hub, including those reached via a raw/* stub (the Karpathy
    indirection). Does not chase records-to-records links.
    """
    hub_path = Path(hub_path)
    body = hub_path.read_text(encoding="utf-8")
    record_paths: list[Path] = []
    raw_paths: list[Path] = []
    for bucket, slug in _LINK_RE.findall(body):
        slug = slug.removesuffix(".md")
        candidate = Path(vault_root) / bucket / f"{slug}.md"
        if not candidate.is_file():
            continue
        if bucket == "records":
            record_paths.append(candidate)
        else:
            raw_paths.append(candidate)
    for raw in raw_paths:
        raw_body = raw.read_text(encoding="utf-8")
        for bucket, slug in _LINK_RE.findall(raw_body):
            if bucket != "records":
                continue
            slug = slug.removesuffix(".md")
            candidate = Path(vault_root) / "records" / f"{slug}.md"
            if candidate.is_file() and candidate not in record_paths:
                record_paths.append(candidate)
    return record_paths
