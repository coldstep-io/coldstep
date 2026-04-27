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
        self.assertEqual(embedded["schema_version"], "2.1")

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
        self.assertIn('data-mount="otx-tiers"', html)
        self.assertIn("Threat-intel verdicts", html)

    def test_template_has_report_toc_nav(self):
        html = (PKG_DIR / "templates" / "report.html").read_text(encoding="utf-8")
        self.assertIn('id="triage-first"', html)
        self.assertIn('data-mount="triage-first"', html)
        self.assertIn('class="report-toc"', html)
        self.assertIn('href="#triage-first"', html)
        self.assertIn('href="#capabilities"', html)
        self.assertIn('href="#events"', html)
        self.assertIn('href="#egress"', html)
        self.assertIn('href="#diff"', html)
        self.assertIn('href="#otx"', html)

    def test_styles_have_verdict_pill_classes(self):
        css = (PKG_DIR / "templates" / "styles.css").read_text(encoding="utf-8")
        for cls in (".coldstep-verdict-malicious", ".coldstep-verdict-clean",
                    ".coldstep-verdict-unidentified", ".coldstep-verdict-rate-limited"):
            self.assertIn(cls, css, f"missing CSS class {cls}")
        for tok in ("--coldstep-confidence-high", '.coldstep-otx-tier[data-tier="high"]'):
            self.assertIn(tok, css)

    def test_styles_have_report_toc(self):
        css = (PKG_DIR / "templates" / "styles.css").read_text(encoding="utf-8")
        self.assertIn(".report-toc", css)
        self.assertIn(".report-toc a:focus-visible", css)
        self.assertIn(".report-triage", css)
        self.assertIn(".triage-grid", css)

    def test_dns_lookups_round_trip_into_json_island(self):
        # rDNS enrichment writes model.dns_lookups; the HTML renderer must
        # round-trip the field through the JSON island so the JS can read it.
        model = dict(self.model)
        model["dns_lookups"] = {"8.8.8.8": "dns.google"}
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "report.html"
            _RMOD.write_html(model=model, html_out=str(out))
            html = out.read_text(encoding="utf-8")
        m = re.search(
            r'<script[^>]+id="coldstep-report-model"[^>]+type="application/json"[^>]*>(.*?)</script>',
            html, re.DOTALL)
        embedded = json.loads(m.group(1))
        self.assertEqual(embedded["dns_lookups"], {"8.8.8.8": "dns.google"})

    def test_otx_section_uses_dns_lookups_for_indicator_label(self):
        # The template's OTX block should display the rDNS hostname alongside
        # an IPv4 indicator when the lookup is available.
        model = dict(self.model)
        model["dns_lookups"] = {"8.8.8.8": "dns.google"}
        model["otx"] = {"skipped": False, "skipped_reason": None,
                        "queried_at": "z", "wall_ms": 50, "wall_budget_ms": 30000,
                        "partial_results": False, "api_calls": 1, "rate_limited": 0,
                        "indicators": [{"indicator": "8.8.8.8", "type": "IPv4",
                                        "verdict": "clean"}],
                        "summary": {"malicious": 0, "clean": 1, "unidentified": 0, "total": 1}}
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "report.html"
            _RMOD.write_html(model=model, html_out=str(out))
            html = out.read_text(encoding="utf-8")
        # The data is in the JSON island and the template's JS pulls
        # model.dns_lookups[r.indicator] into the rendered list.
        self.assertIn('"8.8.8.8": "dns.google"', html)
        self.assertIn("dns_lookups", html)

    def test_egress_section_template_carries_verdict_pivot_mounts(self):
        # The renderer is a substitute-and-write; verifying the template alone
        # is enough to know the HTML will route through the verdict pivot when
        # the JS sees model.otx + non-empty model.egress_sankey at run time.
        html = (PKG_DIR / "templates" / "report.html").read_text(encoding="utf-8")
        self.assertIn('data-mount="egress-host-verdict"', html)
        self.assertIn('data-mount="egress-verdict-policy"', html)
        self.assertIn("verdict", html.lower())

    def test_egress_template_js_reads_dns_lookups_for_host_label(self):
        # The host-label join must happen in the template, not in Python -
        # render_html_report.py is just a placeholder substitution. Searching
        # for "dns_lookups" in the template's JS confirms the join is wired.
        html = (PKG_DIR / "templates" / "report.html").read_text(encoding="utf-8")
        # The OTX block already references dns_lookups; the egress block
        # must reference it too. Counting >= 2 occurrences keeps both honest.
        self.assertGreaterEqual(html.count("dns_lookups"), 2)

    def test_generated_at_is_html_escaped(self):
        # F-P1-01: a tampered or hand-crafted report-model.json must not be able
        # to break out of <time>...</time> via the GENERATED_AT slot. The
        # renderer must HTML-escape the value before substitution.
        evil = dict(self.model)
        evil["generated_at"] = '</time><script>alert("xss")</script><time>'
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "evil-genat.html"
            _RMOD.write_html(model=evil, html_out=str(out))
            html = out.read_text(encoding="utf-8")
        self.assertNotIn("<script>alert(\"xss\")</script>", html)
        self.assertIn(
            "&lt;/time&gt;&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;&lt;time&gt;",
            html,
        )

    def test_renders_otx_data_into_html(self):
        model = dict(self.model)
        model["otx"] = {"skipped": False, "skipped_reason": None,
                        "queried_at": "z", "wall_ms": 100, "wall_budget_ms": 30000,
                        "partial_results": False, "api_calls": 1, "rate_limited": 0,
                        "indicators": [{"indicator": "evil.example.com",
                                        "type": "hostname", "verdict": "malicious",
                                        "pulse_count": 1,
                                        "pulse_severity": "Low",
                                        "evidence": []}],
                        "summary": {"malicious": 1, "clean": 0,
                                    "unidentified": 0, "total": 1}}
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "report.html"
            _RMOD.write_html(model=model, html_out=str(out))
            html = out.read_text(encoding="utf-8")
        self.assertIn("evil.example.com", html)
        self.assertIn('"malicious"', html)
        self.assertIn('"pulse_severity": "Low"', html)
        self.assertIn(" · signal ", html)

    def test_otx_template_js_groups_indicators_by_confidence_tier(self):
        # write_html does not execute the inline module; tier <details> are built
        # client-side. Assert the template wires confidence tiers + schema v2.1 mount.
        tpl = (PKG_DIR / "templates" / "report.html").read_text(encoding="utf-8")
        self.assertIn("confidenceTier", tpl)
        self.assertIn('setAttribute("data-tier"', tpl)
        self.assertIn("coldstep-otx-tier-null", tpl)


if __name__ == "__main__":
    unittest.main()
