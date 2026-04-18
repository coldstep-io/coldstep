import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path


PKG_DIR = Path(__file__).with_name("coldstep_detect_report")
BUILD = PKG_DIR / "build_report_model.py"
RENDER = PKG_DIR / "render_step_summary.py"

_BSPEC = importlib.util.spec_from_file_location("crd_build", BUILD)
_BMOD = importlib.util.module_from_spec(_BSPEC); _BSPEC.loader.exec_module(_BMOD)
_RSPEC = importlib.util.spec_from_file_location("crd_render_summary", RENDER)
_RMOD = importlib.util.module_from_spec(_RSPEC); _RSPEC.loader.exec_module(_RMOD)


class StepSummaryRendererTests(unittest.TestCase):
    def setUp(self):
        self.model = _BMOD.build(
            current_jsonl=str(PKG_DIR / "fixtures" / "coldstep-events.sample.jsonl"),
            baseline_jsonl=str(PKG_DIR / "fixtures" / "baseline-events.sample.jsonl"),
        )

    def _render(self) -> str:
        with tempfile.TemporaryDirectory() as td:
            summary = Path(td) / "summary.md"
            _RMOD.write_summary(model=self.model, summary_path=str(summary))
            return summary.read_text(encoding="utf-8")

    def test_summary_contains_capability_matrix_with_pills(self):
        out = self._render()
        self.assertIn("### Detect Capability Matrix", out)
        self.assertIn("🟢", out)
        self.assertIn("Exec tracing", out)

    def test_summary_contains_mermaid_xychart_for_events_by_type(self):
        out = self._render()
        self.assertIn("```mermaid", out)
        self.assertIn("xychart-beta", out)

    def test_summary_contains_mermaid_sankey_for_egress(self):
        out = self._render()
        self.assertIn("sankey-beta", out)
        self.assertIn("example.com", out)

    def test_summary_contains_diff_table_with_missing_host(self):
        out = self._render()
        self.assertIn("Missing traffic", out)
        self.assertIn("theclouddj.com", out)

    def test_summary_size_well_under_one_mib(self):
        out = self._render()
        self.assertLess(len(out.encode("utf-8")), 256 * 1024)


if __name__ == "__main__":
    unittest.main()
