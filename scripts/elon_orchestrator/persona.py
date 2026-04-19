"""Load persona-dial weights for a named skill from .elon/persona.yml."""
from __future__ import annotations

from pathlib import Path

from scripts.elon_orchestrator import yaml_lite

_NEUTRAL = {"fp": 0.25, "vi": 0.25, "sh": 0.25, "co": 0.25}
_TRAITS = ("fp", "vi", "sh", "co")


def load_persona_dial(skill_name: str, vault_root: Path) -> dict[str, float]:
    """Return {fp, vi, sh, co} weights for skill_name. Returns the neutral dial
    {0.25 each} when the file is missing or the skill has no entry.
    """
    path = Path(vault_root) / ".elon" / "persona.yml"
    if not path.is_file():
        return dict(_NEUTRAL)
    parsed = yaml_lite.parse(path.read_text(encoding="utf-8"))
    skill_block = parsed.get(skill_name)
    if not isinstance(skill_block, dict):
        return dict(_NEUTRAL)
    return {k: float(skill_block.get(k, _NEUTRAL[k])) for k in _TRAITS}
