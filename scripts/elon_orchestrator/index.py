"""Auto-maintain the wiki-hub table inside knowledge/Index.md."""
from __future__ import annotations

import re
from pathlib import Path

_HUB_LINK_RE = re.compile(r"\[\[wiki/([^\]|]+?)\]\]")
_TABLE_ROW_RE = re.compile(r"^\| \[\[wiki/([^\]|]+?)\]\] +\|", re.MULTILINE)
_HUB_TITLE_RE = re.compile(r"^# +(.+?)$", re.MULTILINE)


def append_index_row(hub_path: Path, vault_root: Path) -> None:
    """Insert a row for hub_path into knowledge/Index.md, alphabetically by slug.

    Idempotent: returns silently if the row already exists. Raises ValueError if
    hub_path is not inside knowledge/wiki/.
    """
    hub_path = Path(hub_path)
    vault_root = Path(vault_root)
    try:
        rel = hub_path.relative_to(vault_root)
    except ValueError as exc:
        raise ValueError(f"hub_path {hub_path} not under vault {vault_root}") from exc
    if rel.parts[:1] != ("wiki",):
        raise ValueError(f"hub_path must live under wiki/, got {rel}")
    slug = hub_path.stem
    body = hub_path.read_text(encoding="utf-8")
    title_match = _HUB_TITLE_RE.search(body)
    title = title_match.group(1).strip() if title_match else slug
    index_path = vault_root / "Index.md"
    index_text = index_path.read_text(encoding="utf-8")
    existing = {m.group(1): m for m in _TABLE_ROW_RE.finditer(index_text)}
    if slug in existing:
        return
    new_row = f"| [[wiki/{slug}]] | {title} |"
    insertion_point = None
    for existing_slug, match in existing.items():
        if slug < existing_slug:
            insertion_point = match.start()
            break
    if insertion_point is None:
        # Append after the LAST existing row.
        last = list(existing.values())[-1]
        insertion_point = last.end()
        new_row = "\n" + new_row
    else:
        new_row = new_row + "\n"
    index_text = index_text[:insertion_point] + new_row + index_text[insertion_point:]
    index_path.write_text(index_text, encoding="utf-8", newline="\n")
