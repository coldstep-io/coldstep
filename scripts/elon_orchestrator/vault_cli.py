"""Single entry point for invoking the obsidian-cli skill.

Other elon skills MUST call vault_cli() rather than reaching past Orchestrator
into raw obsidian-cli. The value is the version pin and the single point of
change when obsidian-cli's CLI shape evolves.
"""
from __future__ import annotations

import subprocess

OBSIDIAN_CLI_BIN = "obsidian-cli"


def vault_cli(subcommand: str, *args: str, **kwargs) -> subprocess.CompletedProcess:
    """Invoke obsidian-cli with the given subcommand + args. Captures output by default.

    Does NOT raise on non-zero exit; the caller decides what to do with returncode.
    Pass `timeout=N`, `cwd=...`, `env=...`, etc. via kwargs.
    """
    cmd = [OBSIDIAN_CLI_BIN, subcommand, *args]
    kwargs.setdefault("capture_output", True)
    kwargs.setdefault("check", False)
    return subprocess.run(cmd, **kwargs)
