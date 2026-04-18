import importlib.util
import tempfile
import unittest
from pathlib import Path


PKG_DIR = Path(__file__).with_name("coldstep_detect_report")
BUILD = PKG_DIR / "build_report_model.py"
RENDER = PKG_DIR / "render_step_summary.py"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"could not load {name} from {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_BMOD = _load("crd_build", BUILD)
_RMOD = _load("crd_render_summary", RENDER)


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

    def test_diff_unavailable_renders_explanatory_message(self):
        model = _BMOD.build(
            current_jsonl=str(PKG_DIR / "fixtures" / "coldstep-events.sample.jsonl"),
            baseline_jsonl=None,
        )
        with tempfile.TemporaryDirectory() as td:
            summary = Path(td) / "summary.md"
            _RMOD.write_summary(model=model, summary_path=str(summary))
            out = summary.read_text(encoding="utf-8")
        self.assertIn("_Diff unavailable: no_baseline_provided._", out)

    def test_md_cell_escapes_pipe_and_newline(self):
        # _md_cell is the hardening helper for GFM table cells.
        self.assertEqual(_RMOD._md_cell("a|b"), r"a\|b")
        self.assertEqual(_RMOD._md_cell("a\nb"), "a b")
        self.assertEqual(_RMOD._md_cell("a\\b"), r"a\\b")


if __name__ == "__main__":
    unittest.main()
