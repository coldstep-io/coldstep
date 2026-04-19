import importlib.util
import os
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

    def test_bluf_contains_headings_and_capability_line(self):
        out = self._render()
        self.assertIn("## Coldstep detect — summary", out)
        self.assertIn("**Capabilities:**", out)
        self.assertIn("all pass", out.lower())

    def test_bluf_has_no_mermaid(self):
        out = self._render()
        self.assertNotIn("```mermaid", out)
        self.assertNotIn("xychart-beta", out)
        self.assertNotIn("sankey-beta", out)

    def test_bluf_contains_baseline_diff_counts(self):
        out = self._render()
        self.assertIn("**Baseline diff:** ok", out)
        self.assertIn("new=", out)
        self.assertIn("gone=", out)

    def test_summary_size_small_bluf(self):
        out = self._render()
        self.assertLess(len(out.encode("utf-8")), 16 * 1024)

    def test_diff_unavailable_bluf_line(self):
        model = _BMOD.build(
            current_jsonl=str(PKG_DIR / "fixtures" / "coldstep-events.sample.jsonl"),
            baseline_jsonl=None,
        )
        with tempfile.TemporaryDirectory() as td:
            summary = Path(td) / "summary.md"
            _RMOD.write_summary(model=model, summary_path=str(summary))
            out = summary.read_text(encoding="utf-8")
        self.assertIn("**Baseline diff:** unavailable", out)
        self.assertIn("no_baseline_provided", out)

    def test_md_cell_escapes_pipe_and_newline(self):
        self.assertEqual(_RMOD._md_cell("a|b"), r"a\|b")
        self.assertEqual(_RMOD._md_cell("a\nb"), "a b")
        self.assertEqual(_RMOD._md_cell("a\\b"), r"a\\b")

    def test_bluf_includes_otx_pulse_signal_when_model_has_malicious(self):
        model = dict(self.model)
        model["otx"] = {
            "skipped": False,
            "skipped_reason": None,
            "queried_at": "2026-04-18T17:00:00Z",
            "wall_ms": 100,
            "wall_budget_ms": 30000,
            "partial_results": False,
            "api_calls": 2,
            "rate_limited": 0,
            "indicators": [
                {
                    "indicator": "a.example.com",
                    "type": "hostname",
                    "verdict": "malicious",
                    "pulse_count": 50,
                    "pulse_severity": "Critical",
                    "evidence": [],
                },
                {
                    "indicator": "b.example.com",
                    "type": "hostname",
                    "verdict": "malicious",
                    "pulse_count": 3,
                    "pulse_severity": "Low",
                    "evidence": [],
                },
            ],
            "summary": {"malicious": 2, "clean": 0, "unidentified": 0, "total": 2},
        }
        bluf = _RMOD._bluf_summary_md(model)
        self.assertIn("Critical", bluf)
        self.assertIn("Highest pulse signal", bluf)

    def test_artifact_footer_uses_ns_runner_label_when_set(self):
        old = os.environ.get("NS_RUNNER_LABEL")
        try:
            os.environ["NS_RUNNER_LABEL"] = "ubuntu-latest"
            self.assertIn("coldstep-detect-report-html-ubuntu-latest", _RMOD._artifact_footer_md())
        finally:
            if old is None:
                os.environ.pop("NS_RUNNER_LABEL", None)
            else:
                os.environ["NS_RUNNER_LABEL"] = old

    def test_diff_table_gets_verdict_column_when_otx_present(self):
        model = dict(self.model)
        model["otx"] = {
            "skipped": False, "skipped_reason": None,
            "queried_at": "2026-04-18T17:00:00Z", "wall_ms": 100, "wall_budget_ms": 30000,
            "partial_results": False, "api_calls": 1, "rate_limited": 0,
            "indicators": [
                {"indicator": "theclouddj.com", "type": "hostname", "verdict": "malicious",
                 "pulse_count": 1, "evidence": []},
            ],
            "summary": {"malicious": 1, "clean": 0, "unidentified": 0, "total": 1},
        }
        body = _RMOD._diff_md(model)
        self.assertIn("Verdict", body)
        self.assertIn("🟥", body)

    def test_diff_table_unchanged_when_otx_None(self):
        model = dict(self.model)
        model["otx"] = None
        body = _RMOD._diff_md(model)
        self.assertNotIn("Verdict", body)

    # --- Sankey: 3-column verdict pivot when OTX present ----------------

    def _model_with_sankey(self, edges, otx=None, dns_lookups=None) -> dict:
        m = dict(self.model)
        m["egress_sankey"] = edges
        m["otx"] = otx
        if dns_lookups is not None:
            m["dns_lookups"] = dns_lookups
        return m

    def test_sankey_falls_back_to_2col_when_otx_absent(self):
        m = self._model_with_sankey(
            [{"source": "evil.example.com", "target": "allow", "value": 4,
              "indicators": ["evil.example.com"]}],
            otx=None,
        )
        out = _RMOD._egress_sankey_md(m)
        self.assertIn("host \u2192 policy", out)
        self.assertNotIn("\u2192 verdict \u2192", out)
        self.assertIn("evil.example.com,allow,4", out)

    def test_sankey_falls_back_to_2col_when_otx_skipped(self):
        m = self._model_with_sankey(
            [{"source": "evil.example.com", "target": "allow", "value": 4,
              "indicators": ["evil.example.com"]}],
            otx={"skipped": True, "skipped_reason": "no_api_key",
                 "indicators": [], "summary": {}},
        )
        out = _RMOD._egress_sankey_md(m)
        self.assertNotIn("verdict", out)
        self.assertIn("evil.example.com,allow,4", out)

    def test_sankey_emits_3col_verdict_pivot_when_otx_present(self):
        m = self._model_with_sankey(
            [
                {"source": "evil.example.com", "target": "allow", "value": 5,
                 "indicators": ["evil.example.com"]},
                {"source": "8.8.8.8", "target": "allow", "value": 3,
                 "indicators": ["8.8.8.8"]},
            ],
            otx={"skipped": False,
                 "indicators": [
                     {"indicator": "evil.example.com", "type": "hostname",
                      "verdict": "malicious"},
                     {"indicator": "8.8.8.8", "type": "IPv4", "verdict": "clean"},
                 ],
                 "summary": {"malicious": 1, "clean": 1, "unidentified": 0, "total": 2}},
        )
        out = _RMOD._egress_sankey_md(m)
        self.assertIn("host \u2192 verdict \u2192 policy", out)
        self.assertIn("evil.example.com,malicious,5", out)
        self.assertIn("malicious,allow,5", out)
        self.assertIn("8.8.8.8,clean,3", out)
        self.assertIn("clean,allow,3", out)

    def test_sankey_uses_unverified_bucket_for_indicators_not_in_otx_map(self):
        m = self._model_with_sankey(
            [{"source": "203.0.113.5", "target": "unknown", "value": 7,
              "indicators": ["203.0.113.5"]}],
            otx={"skipped": False,
                 "indicators": [
                     {"indicator": "evil.example.com", "type": "hostname",
                      "verdict": "malicious"},
                 ],
                 "summary": {"malicious": 1, "clean": 0, "unidentified": 0, "total": 1}},
        )
        out = _RMOD._egress_sankey_md(m)
        self.assertIn("203.0.113.5,unverified,7", out)
        self.assertIn("unverified,unknown,7", out)

    def test_sankey_picks_worst_verdict_when_edge_has_mixed_indicators(self):
        m = self._model_with_sankey(
            [{"source": "mixed.example.com", "target": "allow", "value": 2,
              "indicators": ["a.example.com", "b.example.com"]}],
            otx={"skipped": False,
                 "indicators": [
                     {"indicator": "a.example.com", "type": "hostname", "verdict": "clean"},
                     {"indicator": "b.example.com", "type": "hostname", "verdict": "malicious"},
                 ],
                 "summary": {"malicious": 1, "clean": 1, "unidentified": 0, "total": 2}},
        )
        out = _RMOD._egress_sankey_md(m)
        self.assertIn("mixed.example.com,malicious,2", out)
        self.assertIn("malicious,allow,2", out)
        self.assertNotIn("mixed.example.com,clean,2", out)

    def test_sankey_host_label_enriched_with_rdns_when_present(self):
        m = self._model_with_sankey(
            [{"source": "8.8.8.8", "target": "allow", "value": 3,
              "indicators": ["8.8.8.8"]}],
            otx=None,
            dns_lookups={"8.8.8.8": "dns.google"},
        )
        out = _RMOD._egress_sankey_md(m)
        self.assertIn("8.8.8.8 (dns.google),allow,3", out)

    def test_sankey_host_label_unchanged_when_no_rdns(self):
        m = self._model_with_sankey(
            [{"source": "8.8.8.8", "target": "allow", "value": 3,
              "indicators": ["8.8.8.8"]}],
            otx=None,
            dns_lookups={"1.1.1.1": "one.one.one.one"},
        )
        out = _RMOD._egress_sankey_md(m)
        self.assertIn("8.8.8.8,allow,3", out)
        self.assertNotIn("(", out.split("```mermaid")[1])

    def test_diff_table_unchanged_when_otx_skipped(self):
        model = dict(self.model)
        model["otx"] = {"skipped": True, "skipped_reason": "no api key",
                        "queried_at": "z", "wall_ms": 0, "wall_budget_ms": 30000,
                        "partial_results": False, "api_calls": 0, "rate_limited": 0,
                        "indicators": [],
                        "summary": {"malicious": 0, "clean": 0, "unidentified": 0, "total": 0}}
        body = _RMOD._diff_md(model)
        self.assertNotIn("Verdict", body)


if __name__ == "__main__":
    unittest.main()
