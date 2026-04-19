"""Tag taxonomy: load the allowlist from .elon/tags.yml; validate one tag at a time."""
from __future__ import annotations

import difflib
from pathlib import Path

from scripts.elon_orchestrator import yaml_lite


def load_tag_allowlist(vault_root: Path) -> dict[str, str]:
    """Read .elon/tags.yml from the vault. Returns {} if the file is missing."""
    path = Path(vault_root) / ".elon" / "tags.yml"
    if not path.is_file():
        return {}
    parsed = yaml_lite.parse(path.read_text(encoding="utf-8"))
    return {k: str(v) for k, v in parsed.items() if isinstance(v, str)}


def validate_tag(tag: str, vault_root: Path) -> tuple[bool, list[str]]:
    """Return (allowed, suggestions). suggestions is empty when allowed=True or no close match."""
    allowlist = load_tag_allowlist(vault_root)
    if tag in allowlist:
        return True, []
    matches = difflib.get_close_matches(tag, list(allowlist.keys()), n=3, cutoff=0.6)
    return False, list(matches)
