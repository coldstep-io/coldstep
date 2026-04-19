"""Minimal YAML subset for Obsidian frontmatter, tags.yml, persona.yml.

Supports:
  - key: value          (string scalars; numbers stay as strings — caller casts)
  - key: "value"        (quoted strings, preserves embedded colons)
  - key: [a, b, c]      (inline lists)
  - key:                (block lists, 2-space indent)
      - a
      - b
  - one level of nested dict (2-space indent)
  - # comments and blank lines are skipped

Does NOT support: anchors, aliases, multi-doc streams, flow-style maps,
multi-line strings, or anything else PyYAML handles. If you need those, add
PyYAML as a dependency (and explain why the rich Obsidian frontmatter we
write needs it).
"""
from __future__ import annotations

from typing import Any


def parse(text: str) -> dict[str, Any]:
    """Parse a minimal YAML string into a dict. Returns {} on empty input."""
    out: dict[str, Any] = {}
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        raw = lines[i]
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            i += 1
            continue
        if raw.startswith(" "):
            # Stray indented line at top-level — skip (would be picked up by
            # the parent key's block-collection loop below).
            i += 1
            continue
        key, _, value = stripped.partition(":")
        key = key.strip()
        value = value.strip()
        if value == "":
            # Block list or nested dict; peek ahead.
            block, consumed = _read_block(lines, i + 1)
            out[key] = block
            i += 1 + consumed
        elif value.startswith("[") and value.endswith("]"):
            inner = value[1:-1].strip()
            out[key] = [item.strip() for item in inner.split(",") if item.strip()] if inner else []
            i += 1
        elif value.startswith('"') and value.endswith('"'):
            out[key] = value[1:-1]
            i += 1
        else:
            out[key] = value
            i += 1
    return out


def _read_block(lines: list[str], start: int) -> tuple[Any, int]:
    """Read a 2-space-indented block (list or nested dict). Returns (value, lines_consumed)."""
    items_list: list[str] = []
    items_dict: dict[str, str] = {}
    consumed = 0
    while start + consumed < len(lines):
        raw = lines[start + consumed]
        if not raw.startswith("  "):
            break
        body = raw[2:]
        if body.startswith("- "):
            items_list.append(body[2:].strip())
        elif ":" in body:
            k, _, v = body.partition(":")
            items_dict[k.strip()] = v.strip()
        consumed += 1
    if items_list and not items_dict:
        return items_list, consumed
    if items_dict and not items_list:
        return items_dict, consumed
    return ([], 0)


def dump(data: dict[str, Any]) -> str:
    """Serialize a dict to minimal-YAML, preserving insertion order."""
    out_lines: list[str] = []
    for key, value in data.items():
        if isinstance(value, list):
            if len(value) <= 5:
                out_lines.append(f"{key}: [{', '.join(value)}]")
            else:
                out_lines.append(f"{key}:")
                for item in value:
                    out_lines.append(f"  - {item}")
        elif isinstance(value, dict):
            out_lines.append(f"{key}:")
            for k, v in value.items():
                out_lines.append(f"  {k}: {v}")
        else:
            sval = str(value)
            if any(ch in sval for ch in (": ", "#", "\n")):
                out_lines.append(f'{key}: "{sval}"')
            else:
                out_lines.append(f"{key}: {sval}")
    return "\n".join(out_lines) + "\n"
