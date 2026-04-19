import importlib.util
import os
import tempfile
import unittest
from pathlib import Path

PKG_DIR = Path(__file__).with_name("coldstep_detect_report")
RENDER = PKG_DIR / "render_otx_summary.py"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"could not load {name} from {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


MOD = _load("crd_render_otx_summary", RENDER)


def _model_with_otx(otx):
    return {"schema_version": 2, "otx": otx}


class RenderOtxSummaryTests(unittest.TestCase):
    def _capture(self, model: dict) -> str:
        with tempfile.NamedTemporaryFile("w+", encoding="utf-8", delete=False) as tmp:
            tmp_path = tmp.name
        try:
            MOD.write_otx_summary(model, tmp_path)
            return Path(tmp_path).read_text(encoding="utf-8")
        finally:
            os.unlink(tmp_path)

    def test_no_section_when_otx_None(self):
        out = self._capture(_model_with_otx(None))
        self.assertEqual(out, "")

    def test_skipped_renders_notice_only(self):
        otx = {"skipped": True, "skipped_reason": "no api key",
               "queried_at": "2026-04-18T17:00:00Z", "wall_ms": 0, "wall_budget_ms": 30000,
               "partial_results": False, "api_calls": 0, "rate_limited": 0, "indicators": [],
               "summary": {"malicious": 0, "clean": 0, "unidentified": 0, "total": 0}}
        out = self._capture(_model_with_otx(otx))
        self.assertIn("Threat-intel verdicts", out)
        self.assertIn("skipped", out.lower())
        self.assertIn("no api key", out)

    def test_renders_pie_chart_and_table_when_present(self):
        otx = {"skipped": False, "skipped_reason": None,
               "queried_at": "2026-04-18T17:00:00Z", "wall_ms": 100, "wall_budget_ms": 30000,
               "partial_results": False, "api_calls": 3, "rate_limited": 0,
               "indicators": [
                   {"indicator": "evil.example.com", "type": "hostname", "verdict": "malicious",
                    "pulse_count": 7,
                    "evidence": [{"pulse_name": "Lazarus", "tags": ["apt"],
                                  "malware_families": ["AppleJeus"]}]},
                   {"indicator": "8.8.8.8", "type": "IPv4", "verdict": "clean",
                    "validation": ["Listed on Alexa"]},
                   {"indicator": "1.2.3.4", "type": "IPv4", "verdict": "unidentified"},
               ],
               "summary": {"malicious": 1, "clean": 1, "unidentified": 1, "total": 3}}
        out = self._capture(_model_with_otx(otx))
        self.assertIn("Threat-intel verdicts", out)
        self.assertIn("```mermaid", out)
        self.assertIn("pie", out)
        self.assertIn("evil.example.com", out)
        self.assertIn("Lazarus", out)
        self.assertIn("AppleJeus", out)
        # Malicious row appears before clean row.
        self.assertLess(out.index("evil.example.com"), out.index("8.8.8.8"))

    def test_escapes_pipe_in_pulse_name(self):
        otx = {"skipped": False, "skipped_reason": None,
               "queried_at": "z", "wall_ms": 0, "wall_budget_ms": 30000,
               "partial_results": False, "api_calls": 1, "rate_limited": 0,
               "indicators": [
                   {"indicator": "x.com", "type": "hostname", "verdict": "malicious",
                    "pulse_count": 1, "evidence": [{"pulse_name": "naughty | injection",
                                                    "tags": [], "malware_families": []}]},
               ],
               "summary": {"malicious": 1, "clean": 0, "unidentified": 0, "total": 1}}
        out = self._capture(_model_with_otx(otx))
        self.assertIn("naughty \\| injection", out)

    def test_partial_results_rendered_in_status_line(self):
        otx = {"skipped": False, "skipped_reason": None,
               "queried_at": "z", "wall_ms": 30000, "wall_budget_ms": 30000,
               "partial_results": True, "api_calls": 5, "rate_limited": 0,
               "indicators": [
                   {"indicator": "a.com", "type": "hostname", "verdict": "unidentified"},
               ],
               "summary": {"malicious": 0, "clean": 0, "unidentified": 1, "total": 1}}
        out = self._capture(_model_with_otx(otx))
        self.assertIn("partial", out.lower())


if __name__ == "__main__":
    unittest.main()
