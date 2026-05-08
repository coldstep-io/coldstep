#!/usr/bin/env python3
"""
Locate bash and execute scripts/agent-linux-verify.sh without requiring manual Git Bash invocation.

Examples:
    python scripts/agent_linux_verify.py
    python scripts/agent_linux_verify.py --mode fast
    python scripts/agent_linux_verify.py D:\\repos\\coldstep

POSIX:
    chmod +x scripts/agent_linux_verify.py && ./scripts/agent_linux_verify.py
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import List, Optional


def _candidate_git_bash() -> List[Path]:
    out: List[Path] = []
    pf = os.environ.get("ProgramFiles")
    pf86 = os.environ.get("ProgramFiles(x86)")
    for root in (pf, pf86):
        if not root:
            continue
        base = Path(root)
        for rel in ("Git/bin/bash.exe", "Git/usr/bin/bash.exe"):
            p = base / rel
            if p.is_file():
                out.append(p)
    local = Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "Git" / "bin" / "bash.exe"
    if local.is_file():
        out.append(local)
    return out


def _is_windows_stub_bash(p: Path) -> bool:
    """System32/bash.exe and similar forward to WSL and fail without a usable distro."""
    s = str(p.resolve()).replace("/", "\\").lower()
    needles = ("\\system32\\bash.exe", "\\syswow64\\bash.exe", "\\windowsapps\\bash.exe")
    return s.endswith("\\bash.exe") and any(x in s for x in needles)


def _bash_version_ok(path: Path) -> bool:
    try:
        r = subprocess.run(
            [str(path), "--version"],
            capture_output=True,
            timeout=15,
            check=False,
        )
        blob = (r.stdout or b"") + (r.stderr or b"")
        return r.returncode == 0 and bool(blob.strip())
    except OSError:
        return False


def find_bash() -> Optional[Path]:
    candidates: List[Path] = []
    seen: set[str] = set()
    # Prefer Git Bash on Windows before PATH (PATH often resolves to System32 WSL stubs first).
    if sys.platform == "win32":
        for b in _candidate_git_bash():
            if not b.is_file():
                continue
            p = b.resolve()
            sp = str(p)
            if sp not in seen:
                seen.add(sp)
                candidates.append(p)

    for cmd in ("bash", "bash.exe"):
        hit = shutil.which(cmd)
        if hit:
            p = Path(hit).resolve()
            sp = str(p)
            if sp in seen:
                continue
            if sys.platform == "win32" and _is_windows_stub_bash(p):
                continue
            seen.add(sp)
            candidates.append(p)

    for p in candidates:
        if _bash_version_ok(p):
            return p
    return None


def main() -> int:
    scripts_dir = Path(__file__).resolve().parent
    default_repo = scripts_dir.parent

    parser = argparse.ArgumentParser(
        description="Run agent-linux-verify.sh (Docker Linux oracle).",
    )
    parser.add_argument(
        "repo_root",
        nargs="?",
        default=None,
        help="Repository root (default: parent of scripts/).",
    )
    parser.add_argument(
        "-m",
        "--mode",
        choices=("quick", "deep", "fast"),
        default=None,
        help="Set COLDSTEP_VERIFY_MODE for this invocation.",
    )
    args = parser.parse_args()

    repo_root = Path(args.repo_root).resolve() if args.repo_root else default_repo
    verify_sh = repo_root / "scripts" / "agent-linux-verify.sh"
    if not verify_sh.is_file():
        print(f"Missing {verify_sh}", file=sys.stderr)
        return 2

    bash = find_bash()
    if not bash:
        print(
            "Could not find bash.\n"
            "\nFastest setup on Windows: install Git for Windows (bundles bash), then rerun.\n"
            "  winget install --id Git.Git -e\n"
            "\nPowerShell launcher (same requirement): scripts/agent-linux-verify.ps1\n",
            file=sys.stderr,
        )
        return 127

    if shutil.which("docker") is None and shutil.which("docker.exe") is None:
        print("docker CLI not found on PATH.", file=sys.stderr)
        return 127

    env = os.environ.copy()
    if args.mode:
        env["COLDSTEP_VERIFY_MODE"] = args.mode

    print(f"agent_linux_verify.py: bash={bash}", flush=True)
    print(f"agent_linux_verify.py: repo={repo_root}", flush=True)
    if args.mode:
        print(f"agent_linux_verify.py: COLDSTEP_VERIFY_MODE={args.mode}", flush=True)

    result = subprocess.run(
        [str(bash), str(verify_sh), str(repo_root)],
        cwd=str(repo_root),
        env=env,
    )
    return int(result.returncode)


if __name__ == "__main__":
    raise SystemExit(main())
