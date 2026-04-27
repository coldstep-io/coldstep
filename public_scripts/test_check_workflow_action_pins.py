import importlib.util
import tempfile
import unittest
from pathlib import Path


_SCRIPT = Path(__file__).with_name("check_workflow_action_pins.py")
_SPEC = importlib.util.spec_from_file_location("workflow_pins", _SCRIPT)
_MOD = importlib.util.module_from_spec(_SPEC)
assert _SPEC and _SPEC.loader
_SPEC.loader.exec_module(_MOD)


class WorkflowPinTests(unittest.TestCase):
    def test_blocks_main_ref(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "bad.yml"
            p.write_text(
                "jobs:\n  x:\n    runs-on: ubuntu-latest\n    steps:\n"
                "      - uses: actions/checkout@main\n",
                encoding="utf-8",
            )
            errs = _MOD.check_file(p)
            self.assertTrue(any("main" in e for e in errs))

    def test_requires_canonical_marketplace_tag(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "demo.yml"
            p.write_text(
                "jobs:\n  x:\n    runs-on: ubuntu-latest\n    steps:\n"
                "      - uses: coldstep-io/coldstep@v0.1.3\n",
                encoding="utf-8",
            )
            errs = _MOD.check_file(p)
            self.assertTrue(any("coldstep-io/coldstep must pin" in e for e in errs))

    def test_repo_workflows_clean(self):
        wf = _SCRIPT.resolve().parents[1] / ".github" / "workflows"
        if not wf.is_dir():
            self.skipTest("no .github/workflows")
        bad: list[str] = []
        for path in sorted(wf.glob("*.yml")) + sorted(wf.glob("*.yaml")):
            bad.extend(_MOD.check_file(path))
        self.assertEqual([], bad)


if __name__ == "__main__":
    unittest.main()
