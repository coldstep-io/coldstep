"""
Shared helpers: detect UTF-16 (and UTF-16-like) text that breaks Go, YAML, and TS
when Windows tools save as "Unicode". Used by CI assert and Cursor afterFileEdit hook.
"""

from __future__ import annotations

from pathlib import Path

# Extensions we treat as UTF-8 text in this repo (keep in sync with assert_utf8_text.py).
_SUFFIXES = frozenset({".go", ".ts", ".yml", ".yaml", ".md", ".json", ".mod"})
_SPECIAL_NAMES = frozenset({"action.yml", ".editorconfig"})


def is_candidate(path: Path) -> bool:
    name = path.name.lower()
    if name in _SPECIAL_NAMES:
        return True
    return path.suffix.lower() in _SUFFIXES


def looks_utf16(b: bytes) -> bool:
    if b.startswith((b"\xff\xfe", b"\xfe\xff")):
        return True
    if len(b) < 4:
        return False
    return (
        0x20 <= b[0] < 0x7F
        and b[1] == 0
        and 0x20 <= b[2] < 0x7F
        and b[3] == 0
    )


def decode_utf16_to_str(b: bytes) -> str:
    if b.startswith(b"\xff\xfe"):
        return b[2:].decode("utf-16-le", errors="replace")
    if b.startswith(b"\xfe\xff"):
        return b[2:].decode("utf-16-be", errors="replace")
    return b.decode("utf-16-le", errors="replace")


def fix_file(path: Path) -> bool:
    """
    If path is a candidate and content looks UTF-16, rewrite as UTF-8 (no BOM).
    Returns True if the file was changed.
    """
    if not path.is_file():
        return False
    if not is_candidate(path):
        return False
    try:
        b = path.read_bytes()
    except OSError:
        return False
    if not b or not looks_utf16(b):
        return False
    text = decode_utf16_to_str(b)
    new_b = text.encode("utf-8")
    if new_b == b:
        return False
    path.write_bytes(new_b)
    return True
