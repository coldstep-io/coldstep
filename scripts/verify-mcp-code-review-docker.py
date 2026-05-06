#!/usr/bin/env python3
"""
End-to-end MCP stdio proof against the Docker image (no mocks):

spawn `docker run --rm -i <image>`, run MCP initialize + tools/list + tools/call,
using real bytes read from bpf/trace_connect.bpf.c in this repo.
Requires: Docker, Python with `mcp` + `anyio` on the host (same stack Cursor-style clients use).
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
IMAGE_TAG = os.environ.get("IMAGE_TAG", "coldstep-code-review-mcp:smoke")


def _bpf_snippet() -> str:
    path = REPO_ROOT / "bpf" / "trace_connect.bpf.c"
    data = path.read_text(encoding="utf-8")
    return data[:3500]


def _tool_text(result: types.CallToolResult) -> str:
    parts: list[str] = []
    for block in result.content:
        if isinstance(block, types.TextContent):
            parts.append(block.text)
    return "\n".join(parts)


async def _run() -> None:
    snippet = _bpf_snippet()
    server = StdioServerParameters(
        command="docker",
        args=["run", "--rm", "-i", IMAGE_TAG],
    )
    async with stdio_client(server) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            listed = await session.list_tools()
            names = {t.name for t in listed.tools}
            required = {
                "get_expert_system_prompt",
                "sequential_review_thought",
                "review_checklist",
                "prepare_review_packet",
            }
            missing = required - names
            if missing:
                raise SystemExit(f"missing tools: {missing}; got {sorted(names)}")

            r_expert = await session.call_tool("get_expert_system_prompt", {})
            expert = _tool_text(r_expert)
            if len(expert) < 200:
                raise SystemExit("get_expert_system_prompt returned too little text")

            r_pack = await session.call_tool(
                "prepare_review_packet",
                {
                    "code": snippet,
                    "language": "c",
                    "focus": "BPF verifier and ringbuf map usage",
                },
            )
            packet = _tool_text(r_pack)
            if "--- expert system prompt ---" not in packet:
                raise SystemExit("packet missing prompt banner")
            if "--- code (c) ---" not in packet:
                raise SystemExit("packet missing code banner")
            if "LICENSE" not in snippet and "trace_connect" not in snippet:
                raise SystemExit("unexpected snippet content")

            print("MCP_OK real_stdio_session")
            print(f"tools_listed={len(listed.tools)}")
            print(f"expert_prompt_chars={len(expert)}")
            print(f"packet_chars={len(packet)}")


def main() -> None:
    anyio.run(_run)


if __name__ == "__main__":
    main()
    sys.exit(0)
