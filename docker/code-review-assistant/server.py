#!/usr/bin/env python3
"""MCP server: expert code-review assistant with sequential-review tooling (no external APIs)."""

from __future__ import annotations

import json
from pathlib import Path

from mcp.server.fastmcp import FastMCP

PROMPT_PATH = Path(__file__).resolve().parent / "prompts" / "expert_system.txt"


def _load_expert_prompt() -> str:
    return PROMPT_PATH.read_text(encoding="utf-8")


def _checklist_for(language: str, context: str) -> str:
    lang = language.strip().lower()
    base = {
        "go": (
            "Errors and wrapping; context cancellation; goroutine shutdown; data races; "
            "tests for concurrency; no silent error drops."
        ),
        "c": (
            "UB and integer overflow; lifetimes; initialization; strict aliasing; "
            "BPF: verifier-friendly patterns only."
        ),
        "bpf": (
            "Verifier: bounded control flow; stack usage; map safety; helper correctness; "
            "portability across kernels."
        ),
        "ebpf": "Same as bpf; add BTF/CO-RE notes when reviewing relocation-heavy code.",
        "yaml": (
            "Schema validity for target (e.g. GitHub Actions); injection via expressions; "
            "permissions least-privilege; pin actions."
        ),
        "github_actions": (
            "runs-on ubuntu-latest implications; permissions block; secrets usage; "
            "workflow_dispatch/fork safety; action pinning."
        ),
    }
    key = lang if lang in base else "generic"
    generic = (
        "Security boundaries; error handling; tests; docs for public APIs; performance "
        "only when materially relevant."
    )
    body = base.get(key, generic)
    extra = f" Additional context from reviewer: {context}" if context.strip() else ""
    return f"[{key}] {body}{extra}"


mcp = FastMCP(
    "code-review-expert",
    instructions=(
        "Expert code review coverage for RFCs, BPF/eBPF, GitHub Actions (Ubuntu runners), "
        "Go, and C. No network or API keys: use get_expert_system_prompt, "
        "prepare_review_packet, review_checklist, and sequential_review_thought with your "
        "local IDE model."
    ),
)


@mcp.tool()
def get_expert_system_prompt() -> str:
    """Return the full expert reviewer system prompt (RFC/BPF/Actions/Go/C)."""
    return _load_expert_prompt()


@mcp.tool()
def sequential_review_thought(
    thought: str,
    next_thought_needed: bool,
    thought_number: int,
    total_thoughts: int,
    is_revision: bool | None = None,
    revises_thought: int | None = None,
    branch_from_thought: int | None = None,
    branch_id: str | None = None,
    needs_more_thoughts: bool | None = None,
) -> str:
    """
    Mirror sequential-thinking style steps for code review (dynamic CoT).
    Returns a JSON record echoing inputs so clients can build a reasoning chain.
    """
    record = {
        "thoughtNumber": thought_number,
        "totalThoughts": total_thoughts,
        "nextThoughtNeeded": next_thought_needed,
        "thought": thought,
        "isRevision": bool(is_revision),
        "revisesThought": revises_thought,
        "branchFromThought": branch_from_thought,
        "branchId": branch_id,
        "needsMoreThoughts": bool(needs_more_thoughts),
    }
    return json.dumps(record, ensure_ascii=False)


@mcp.tool()
def review_checklist(
    language: str,
    context: str = "",
) -> str:
    """
    Return a domain checklist hint for the given language or area (e.g. go, c, bpf, yaml, github_actions).
    """
    return _checklist_for(language, context)


@mcp.tool()
def prepare_review_packet(
    code: str,
    language: str,
    focus: str = "",
) -> str:
    """
    Assemble system prompt, checklist, optional focus, and code into one message for the
    host IDE or chat model. No network calls and no API keys.
    """
    parts = [
        "--- expert system prompt ---",
        _load_expert_prompt(),
        "",
        "--- checklist ---",
        _checklist_for(language, ""),
        "",
    ]
    if focus.strip():
        parts.extend(["--- reviewer focus ---", focus.strip(), ""])
    parts.extend(
        [
            f"--- code ({language}) ---",
            code,
        ]
    )
    return "\n".join(parts)


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
