#!/usr/bin/env python3
"""
Repair bpftool `btf dump format c` output when integer typedefs appear after forward
declarations that reference __u8 / __s16 / etc. (clang then fails with unknown type).

Idempotent: insertion is skipped when the CO-RE integer typedef shim immediately follows the
standard `#ifndef __VMLINUX_H__` preamble (same layout as libbpf-generated headers).

Removes duplicate copies of the same typedef block when bpftool emits them twice.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Optional

# Matches the CO-RE shim block at the top of a typical libbpf-style vmlinux.h (through u64 aliases).
_INT_TYPEDEF_BLOCK = """typedef signed char __s8;

typedef unsigned char __u8;

typedef short int __s16;

typedef short unsigned int __u16;

typedef int __s32;

typedef unsigned int __u32;

typedef long long int __s64;

typedef long long unsigned int __u64;

typedef __s8 s8;

typedef __u8 u8;

typedef __s16 s16;

typedef __u16 u16;

typedef __s32 s32;

typedef __u32 u32;

typedef __s64 s64;

typedef __u64 u64;

"""

def _vmlinux_preamble_match(text: str) -> Optional[re.Match[str]]:
    long_pat = re.compile(
        r"(?ms)^#ifndef __VMLINUX_H__\n#define __VMLINUX_H__\n\n"
        r"#ifndef BPF_NO_PRESERVE_ACCESS_INDEX\n"
        r"#pragma clang attribute push \(__attribute__\(\(preserve_access_index\)\), apply_to = record\)\n"
        r"#endif\n\n",
    )
    m = long_pat.match(text)
    if m:
        return m
    short_pat = re.compile(r"(?ms)^#ifndef __VMLINUX_H__\n#define __VMLINUX_H__\n\n")
    return short_pat.match(text)


def _needs_insert(text: str) -> bool:
    """
    True when integer typedefs are not placed immediately after the vmlinux.h preamble.
    A substring scan is insufficient: bpftool can emit a late `typedef unsigned char __u8`
    after structs that already reference `__u8`, which still breaks clang.
    """
    m = _vmlinux_preamble_match(text)
    if not m:
        return False
    rest = text[m.end() :]
    pos = 0
    while pos < len(rest) and rest[pos] in " \t\n\r":
        pos += 1
    tail = rest[pos:]
    # Require the canonical opening pair (some dumps emit __s8 alone before structs).
    return not tail.startswith(
        "typedef signed char __s8;\n\ntypedef unsigned char __u8;"
    )


def _insert_after_preamble(text: str) -> str:
    """Insert integer typedef block immediately after the standard vmlinux.h preamble."""
    m = _vmlinux_preamble_match(text)
    if m:
        end = m.end()
        return text[:end] + _INT_TYPEDEF_BLOCK + "\n" + text[end:]
    return text


def _strip_duplicate_typedef_blocks(text: str) -> str:
    """Remove repeat occurrences of the integer typedef block (keep the first)."""
    lines = text.splitlines(keepends=True)
    block_lines = _INT_TYPEDEF_BLOCK.splitlines(keepends=True)
    n = len(block_lines)
    out: list[str] = []
    i = 0
    seen = False
    while i < len(lines):
        if (
            i + n <= len(lines)
            and lines[i : i + n] == block_lines
        ):
            if seen:
                i += n
                continue
            seen = True
        out.extend(lines[i : i + 1])
        i += 1
    return "".join(out)


def fix_vmlinux(path: Path) -> None:
    raw = path.read_text(encoding="utf-8")
    text = raw.replace("\r\n", "\n")
    if _needs_insert(text):
        text = _insert_after_preamble(text)
        # Inserted block ends with a blank line; bpftool output often had another blank
        # line before the next section — collapse to a single spacer (\n\n) like committed headers.
        text = re.sub(
            r"(typedef __u64 u64;\n)\n\n(\n)(enum \{)",
            r"\1\n\3",
            text,
            count=1,
        )
    text = _strip_duplicate_typedef_blocks(text)
    orig_norm = raw.replace("\r\n", "\n")
    if text != orig_norm:
        path.write_text(text, encoding="utf-8")


def main() -> None:
    if len(sys.argv) != 2:
        print("usage: ensure_vmlinux_int_typedefs.py <path/to/bpf/vmlinux.h>", file=sys.stderr)
        sys.exit(2)
    p = Path(sys.argv[1])
    if not p.is_file() or p.stat().st_size == 0:
        return
    fix_vmlinux(p)


if __name__ == "__main__":
    main()
