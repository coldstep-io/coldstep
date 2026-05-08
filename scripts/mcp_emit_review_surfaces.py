#!/usr/bin/env python3
"""
Real MCP stdio session (Docker image): pull the container rubric once, then per-surface
checklists from MCP; attach capped source from this repo on the host (avoids huge duplicate
prompts and MCP message size limits).

  docker build -t coldstep-code-review-mcp:local docker/code-review-assistant
  python scripts/mcp_emit_review_surfaces.py > review-surfaces.md

Requires: Docker, Python mcp + anyio.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import anyio
import mcp.types as types
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

REPO_ROOT = Path(__file__).resolve().parents[1]
IMAGE_TAG = os.environ.get("IMAGE_TAG", "coldstep-code-review-mcp:local")

# (relative path, language tag for checklist, max_chars, focus context for checklist)
SURFACES: list[tuple[str, str, int, str]] = [
    (
        "bpf/trace_connect.bpf.c",
        "c",
        6000,
        "BPF verifier / ringbuf / syscall paths",
    ),
    (
        "internal/agent/agent_linux.go",
        "go",
        8000,
        "Agent lifecycle and ring readers",
    ),
    (
        "action.yml",
        "yaml",
        4000,
        "Composite action contract",
    ),
    (
        ".github/workflows/coldstep-ci.yml",
        "github_actions",
        6000,
        "Reusable workflow entry",
    ),
]


def _tool_text(result: types.CallToolResult) -> str:
    parts: list[str] = []
    for block in result.content:
        if isinstance(block, types.TextContent):
            parts.append(block.text)
    return "\n".join(parts)


def _read_cap(rel: str, max_chars: int) -> str:
    p = REPO_ROOT / rel
    data = p.read_text(encoding="utf-8")
    if len(data) > max_chars:
        data = data[:max_chars] + "\n\n[… truncated …]\n"
    return data


async def _run() -> None:
    server = StdioServerParameters(
        command="docker",
        args=["run", "--rm", "-i", IMAGE_TAG],
    )
    async with stdio_client(server) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            r_prompt = await session.call_tool("get_expert_system_prompt", {})
            expert = _tool_text(r_prompt)

            print("# Repo review surfaces (container rubric + checklists)\n")
            print(f"_Image:_ `{IMAGE_TAG}`\n")
            print("## Expert system prompt (from MCP `get_expert_system_prompt`)\n")
            print(expert)
            print("\n---\n")

            for rel, lang, cap, ctx in SURFACES:
                path = REPO_ROOT / rel
                if not path.is_file():
                    print(f"\n## `{rel}` — _missing_\n")
                    continue
                r_cl = await session.call_tool(
                    "review_checklist",
                    {"language": lang, "context": ctx},
                )
                checklist = _tool_text(r_cl)
                code = _read_cap(rel, cap)
                print(f"\n## `{rel}`\n")
                print(f"**Checklist ({lang}):** {checklist}\n")
                print(f"```{_fence_lang(lang)}\n{code}\n```\n")


def _fence_lang(lang: str) -> str:
    if lang == "github_actions":
        return "yaml"
    if lang in ("c", "go"):
        return lang
    return "yaml"


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except OSError:
            pass
    anyio.run(_run)


if __name__ == "__main__":
    main()
