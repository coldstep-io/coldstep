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
    return {"schema_version": "2.1", "otx": otx}


class RenderOtxSummaryTests(unittest.TestCase):
    """`_section` preserves OTX markdown formatting for regression; Tier-1 uses BLUF only."""

    def _legacy_section(self, model: dict) -> str:
        return MOD._section(model)

    def _capture_write(self, model: dict) -> str:
        with tempfile.NamedTemporaryFile("w+", encoding="utf-8", delete=False) as tmp:
            tmp_path = tmp.name
        try:
            MOD.write_otx_summary(model, tmp_path)
            return Path(tmp_path).read_text(encoding="utf-8")
        finally:
            os.unlink(tmp_path)

    def test_write_otx_summary_does_not_append_to_file(self):
        otx = {"skipped": True, "skipped_reason": "no api key",
               "queried_at": "2026-04-18T17:00:00Z", "wall_ms": 0, "wall_budget_ms": 30000,
               "partial_results": False, "api_calls": 0, "rate_limited": 0, "indicators": [],
               "summary": {"malicious": 0, "clean": 0, "unidentified": 0, "total": 0}}
        self.assertEqual(self._capture_write(_model_with_otx(otx)), "")

    def test_section_empty_when_otx_absent(self):
        self.assertEqual(self._legacy_section(_model_with_otx(None)), "")

    def test_skipped_section_renders_notice_only(self):
        otx = {"skipped": True, "skipped_reason": "no api key",
               "queried_at": "2026-04-18T17:00:00Z", "wall_ms": 0, "wall_budget_ms": 30000,
               "partial_results": False, "api_calls": 0, "rate_limited": 0, "indicators": [],
               "summary": {"malicious": 0, "clean": 0, "unidentified": 0, "total": 0}}
        out = self._legacy_section(_model_with_otx(otx))
        self.assertIn("Threat-intel verdicts", out)
        self.assertIn("skipped", out.lower())
        self.assertIn("no api key", out)

    def test_section_renders_pie_chart_and_table_when_present(self):
        otx = {"skipped": False, "skipped_reason": None,
               "queried_at": "2026-04-18T17:00:00Z", "wall_ms": 100, "wall_budget_ms": 30000,
               "partial_results": False, "api_calls": 3, "rate_limited": 0,
               "indicators": [
                   {"indicator": "evil.example.com", "type": "hostname", "verdict": "malicious",
                    "pulse_count": 7,
                    "pulse_severity": "Medium",
                    "evidence": [{"pulse_name": "Lazarus", "tags": ["apt"],
                                  "malware_families": ["AppleJeus"]}]},
                   {"indicator": "8.8.8.8", "type": "IPv4", "verdict": "clean",
                    "validation": ["Listed on Alexa"]},
                   {"indicator": "1.2.3.4", "type": "IPv4", "verdict": "unidentified"},
               ],
               "summary": {"malicious": 1, "clean": 1, "unidentified": 1, "total": 3}}
        out = self._legacy_section(_model_with_otx(otx))
        self.assertIn("Threat-intel verdicts", out)
        self.assertIn("```mermaid", out)
        self.assertIn("pie", out)
        self.assertIn("evil.example.com", out)
        self.assertIn("| Severity |", out)
        self.assertIn("Medium", out)
        self.assertIn("Lazarus", out)
        self.assertIn("AppleJeus", out)
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
        out = self._legacy_section(_model_with_otx(otx))
        self.assertIn("naughty \\| injection", out)

    def test_allowlisted_count_and_source_surface_in_section(self):
        otx = {"skipped": False, "skipped_reason": None,
               "queried_at": "2026-04-18T17:00:00Z", "wall_ms": 0, "wall_budget_ms": 30000,
               "partial_results": False, "api_calls": 0, "rate_limited": 0,
               "allowlisted": 2,
               "indicators": [
                   {"indicator": "127.0.0.1", "type": "IPv4", "verdict": "clean",
                    "source": "allowlist", "reason": "loopback"},
                   {"indicator": "127.99.0.7", "type": "IPv4", "verdict": "clean",
                    "source": "allowlist", "reason": "loopback"},
               ],
               "summary": {"malicious": 0, "clean": 2, "unidentified": 0, "total": 2}}
        out = self._legacy_section(_model_with_otx(otx))
        self.assertIn("Threat-intel verdicts", out)
        self.assertIn("2 from allowlist", out)
        self.assertIn("127.0.0.1", out)
        self.assertIn("allowlist: loopback", out)

    def test_allowlist_and_otx_rows_distinguishable(self):
        otx = {"skipped": False, "skipped_reason": None,
               "queried_at": "z", "wall_ms": 50, "wall_budget_ms": 30000,
               "partial_results": False, "api_calls": 1, "rate_limited": 0,
               "allowlisted": 1,
               "indicators": [
                   {"indicator": "8.8.8.8", "type": "IPv4", "verdict": "clean",
                    "source": "otx", "validation": ["Listed on Alexa"]},
                   {"indicator": "127.0.0.1", "type": "IPv4", "verdict": "clean",
                    "source": "allowlist", "reason": "loopback"},
               ],
               "summary": {"malicious": 0, "clean": 2, "unidentified": 0, "total": 2}}
        out = self._legacy_section(_model_with_otx(otx))
        line_8888 = [ln for ln in out.splitlines() if "8.8.8.8" in ln][0]
        self.assertNotIn("allowlist", line_8888)
        line_local = [ln for ln in out.splitlines() if "127.0.0.1" in ln][0]
        self.assertIn("allowlist: loopback", line_local)

    def test_hostname_column_appears_when_dns_lookups_present(self):
        otx = {"skipped": False, "skipped_reason": None,
               "queried_at": "z", "wall_ms": 50, "wall_budget_ms": 30000,
               "partial_results": False, "api_calls": 1, "rate_limited": 0,
               "indicators": [
                   {"indicator": "8.8.8.8", "type": "IPv4", "verdict": "clean",
                    "validation": ["Listed on Alexa"]},
                   {"indicator": "evil.example.com", "type": "hostname", "verdict": "malicious",
                    "pulse_count": 3,
                    "evidence": [{"pulse_name": "Lazarus", "tags": [], "malware_families": []}]},
               ],
               "summary": {"malicious": 1, "clean": 1, "unidentified": 0, "total": 2}}
        model = {"schema_version": "2.1", "otx": otx,
                 "dns_lookups": {"8.8.8.8": "dns.google"}}
        out = self._legacy_section(model)
        self.assertIn("Hostname", out)
        self.assertIn("dns.google", out)

        def _indicator_cell(ln: str) -> str | None:
            cells = [c.strip() for c in ln.split("|")]
            if len(cells) <= 2:
                return None
            return cells[1].strip("`").strip()

        line_evil = [ln for ln in out.splitlines()
                     if _indicator_cell(ln) == "evil.example.com"][0]
        self.assertNotIn("evil.example.com (evil.example.com)", line_evil)

    def test_no_hostname_column_when_no_lookups(self):
        otx = {"skipped": False, "skipped_reason": None,
               "queried_at": "z", "wall_ms": 50, "wall_budget_ms": 30000,
               "partial_results": False, "api_calls": 1, "rate_limited": 0,
               "indicators": [
                   {"indicator": "8.8.8.8", "type": "IPv4", "verdict": "clean"},
               ],
               "summary": {"malicious": 0, "clean": 1, "unidentified": 0, "total": 1}}
        out = self._legacy_section(_model_with_otx(otx))
        self.assertNotIn("| Hostname |", out)

    def test_partial_results_rendered_in_status_line(self):
        otx = {"skipped": False, "skipped_reason": None,
               "queried_at": "z", "wall_ms": 30000, "wall_budget_ms": 30000,
               "partial_results": True, "api_calls": 5, "rate_limited": 0,
               "indicators": [
                   {"indicator": "a.com", "type": "hostname", "verdict": "unidentified"},
               ],
               "summary": {"malicious": 0, "clean": 0, "unidentified": 1, "total": 1}}
        out = self._legacy_section(_model_with_otx(otx))
        self.assertIn("partial", out.lower())


class TierSplitTests(unittest.TestCase):
    def _legacy_section(self, model: dict) -> str:
        return MOD._section(model)

    def test_high_tier_details_and_why_column(self):
        otx = {"skipped": False, "skipped_reason": None,
               "queried_at": "z", "wall_ms": 10, "wall_budget_ms": 30000,
               "partial_results": False, "api_calls": 1, "rate_limited": 0,
               "indicators": [
                   {"indicator": "evil.com", "type": "hostname", "verdict": "malicious",
                    "confidence": "high", "pulse_count": 3,
                    "confidence_reasons": ["tag:malware"],
                    "evidence": [{"pulse_name": "P", "malware_families": []}]},
               ],
               "summary": {"malicious": 1, "clean": 0, "unidentified": 0, "total": 1}}
        out = self._legacy_section(_model_with_otx(otx))
        self.assertIn("High-confidence malicious (1)", out)
        self.assertIn("<details open>", out)
        self.assertIn("tag:malware", out)

    def test_legacy_malicious_without_confidence_defaults_to_high(self):
        otx = {"skipped": False, "skipped_reason": None,
               "queried_at": "z", "wall_ms": 10, "wall_budget_ms": 30000,
               "partial_results": False, "api_calls": 1, "rate_limited": 0,
               "indicators": [
                   {"indicator": "legacy.bad", "type": "hostname", "verdict": "malicious",
                    "pulse_count": 1,
                    "evidence": [{"pulse_name": "Old"}]},
               ],
               "summary": {"malicious": 1, "clean": 0, "unidentified": 0, "total": 1}}
        out = self._legacy_section(_model_with_otx(otx))
        self.assertIn("High-confidence malicious (1)", out)

    def test_medium_and_low_tiers_render_when_present(self):
        otx = {"skipped": False, "skipped_reason": None,
               "queried_at": "z", "wall_ms": 10, "wall_budget_ms": 30000,
               "partial_results": False, "api_calls": 3, "rate_limited": 0,
               "indicators": [
                   {"indicator": "h.com", "type": "hostname", "verdict": "malicious",
                    "confidence": "high", "pulse_count": 1, "evidence": []},
                   {"indicator": "m.com", "type": "hostname", "verdict": "malicious",
                    "confidence": "medium", "pulse_count": 1, "evidence": []},
                   {"indicator": "l.com", "type": "hostname", "verdict": "malicious",
                    "confidence": "low", "pulse_count": 1, "evidence": []},
               ],
               "summary": {"malicious": 3, "clean": 0, "unidentified": 0, "total": 3}}
        out = self._legacy_section(_model_with_otx(otx))
        self.assertIn("Medium-confidence malicious (1)", out)
        self.assertIn("Low-confidence malicious (1)", out)

    def test_filter_drops_appears_in_status(self):
        otx = {"skipped": False, "skipped_reason": None,
               "queried_at": "z", "wall_ms": 1, "wall_budget_ms": 30000,
               "partial_results": False, "api_calls": 0, "rate_limited": 0,
               "filter_drops": 12,
               "indicators": [],
               "summary": {"malicious": 0, "clean": 0, "unidentified": 0, "total": 0}}
        out = self._legacy_section(_model_with_otx(otx))
        self.assertIn("filtered 12 pulse", out)

    def test_other_verdicts_bucket_for_non_malicious(self):
        otx = {"skipped": False, "skipped_reason": None,
               "queried_at": "z", "wall_ms": 10, "wall_budget_ms": 30000,
               "partial_results": False, "api_calls": 1, "rate_limited": 0,
               "indicators": [
                   {"indicator": "8.8.8.8", "type": "IPv4", "verdict": "clean",
                    "validation": ["Listed on Alexa"]},
               ],
               "summary": {"malicious": 0, "clean": 1, "unidentified": 0, "total": 1}}
        out = self._legacy_section(_model_with_otx(otx))
        self.assertIn("Other verdicts (1)", out)


if __name__ == "__main__":
    unittest.main()
