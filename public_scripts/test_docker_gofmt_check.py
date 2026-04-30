"""Smoke test: docker_gofmt_check.sh exists and is valid bash."""

from __future__ import annotations

import os
import shutil
import subprocess
import unittest
from pathlib import Path


class TestDockerGofmtCheck(unittest.TestCase):
    def test_script_exists_and_passes_bash_syntax_check(self) -> None:
        script = Path(__file__).resolve().parent / "docker_gofmt_check.sh"
        self.assertTrue(script.is_file(), msg=f"missing {script}")
        head = script.read_text(encoding="utf-8")[:64]
        self.assertTrue(head.startswith("#!/"), msg="expected shell shebang")
        if os.name == "nt":
            self.skipTest("bash -n not reliable on Windows hosts; CI runs on Linux")
        bash = shutil.which("bash")
        if bash is None:
            self.skipTest("bash not on PATH")
        r = subprocess.run(
            [bash, "-n", str(script)],
            capture_output=True,
            text=True,
        )
        self.assertEqual(r.returncode, 0, msg=r.stderr or r.stdout)


if __name__ == "__main__":
    unittest.main()
