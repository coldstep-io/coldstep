import importlib.util
import json
import re
import tempfile
import unittest
from pathlib import Path


PKG_DIR = Path(__file__).with_name("coldstep_detect_report")
BUILD = PKG_DIR / "build_report_model.py"
RENDER = PKG_DIR / "render_html_report.py"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"could not load {name} from {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_BMOD = _load("crd_build", BUILD)
_RMOD = _load("crd_render_html", RENDER)


class HtmlReportRendererTests(unittest.TestCase):
    def setUp(self):
        self.model = _BMOD.build(
            current_jsonl=str(PKG_DIR / "fixtures" / "coldstep-events.sample.jsonl"),
            baseline_jsonl=str(PKG_DIR / "fixtures" / "baseline-events.sample.jsonl"),
        )

    def _render(self) -> str:
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "report.html"
            _RMOD.write_html(model=self.model, html_out=str(out))
            return out.read_text(encoding="utf-8")

    def test_html_is_self_contained_html5(self):
        html = self._render()
        self.assertTrue(html.startswith("<!doctype html>") or html.startswith("<!DOCTYPE html>"))
        self.assertIn("<title>Coldstep detect-mode report</title>", html)

    def test_html_inlines_report_model_json(self):
        html = self._render()
        self.assertIn('id="coldstep-report-model"', html)
        m = re.search(
            r'<script[^>]+id="coldstep-report-model"[^>]+type="application/json"[^>]*>(.*?)</script>',
            html, re.DOTALL,
        )
        self.assertIsNotNone(m, "missing inline JSON island")
        embedded = json.loads(m.group(1))
        self.assertEqual(embedded["schema_version"], 2)

    def test_html_loads_observable_plot_with_sri(self):
        html = self._render()
        self.assertIn("@observablehq/plot", html)
        self.assertIn('integrity="sha384-', html)
        self.assertIn('crossorigin="anonymous"', html)

    def test_html_contains_no_unescaped_closing_script_for_json(self):
        evil = dict(self.model)
        evil["_evil"] = "</script><script>alert(1)</script>"
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "evil.html"
            _RMOD.write_html(model=evil, html_out=str(out))
            html = out.read_text(encoding="utf-8")
        self.assertNotIn("</script><script>alert(1)</script>", html)

    def test_template_has_otx_section_anchor(self):
        # The renderer just substitutes MODEL_JSON into a fixed template, so the
        # template must contain the OTX section markup that the embedded JS reads.
        html = (PKG_DIR / "templates" / "report.html").read_text(encoding="utf-8")
        self.assertIn('data-section="otx"', html)
        self.assertIn("Threat-intel verdicts", html)

    def test_styles_have_verdict_pill_classes(self):
        css = (PKG_DIR / "templates" / "styles.css").read_text(encoding="utf-8")
        for cls in (".coldstep-verdict-malicious", ".coldstep-verdict-clean",
                    ".coldstep-verdict-unidentified", ".coldstep-verdict-rate-limited"):
            self.assertIn(cls, css, f"missing CSS class {cls}")

    def test_renders_otx_data_into_html(self):
        model = dict(self.model)
        model["otx"] = {"skipped": False, "skipped_reason": None,
                        "queried_at": "z", "wall_ms": 100, "wall_budget_ms": 30000,
                        "partial_results": False, "api_calls": 1, "rate_limited": 0,
                        "indicators": [{"indicator": "evil.example.com",
                                        "type": "hostname", "verdict": "malicious",
                                        "pulse_count": 1, "evidence": []}],
                        "summary": {"malicious": 1, "clean": 0,
                                    "unidentified": 0, "total": 1}}
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "report.html"
            _RMOD.write_html(model=model, html_out=str(out))
            html = out.read_text(encoding="utf-8")
        self.assertIn("evil.example.com", html)
        self.assertIn('"malicious"', html)


if __name__ == "__main__":
    unittest.main()
