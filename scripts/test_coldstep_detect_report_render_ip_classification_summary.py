import tempfile
import unittest
from pathlib import Path

from scripts.coldstep_detect_report.render_ip_classification_summary import (
    render_markdown,
    write_summary,
)


class RenderIPClassificationSummaryTests(unittest.TestCase):
    def test_writes_ip_fqdn_rdns_classification_table(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            summary = Path(td) / "summary.md"
            model = {
                "ip_classification": [
                    {
                        "ip": "1.1.1.1",
                        "fqdn": "one.one.one.one",
                        "rdns": "one.one.one.one",
                        "classification": "clean",
                        "severity": "Low",
                        "confidence": "B",
                        "evidence_flags": ["OTX:clean"],
                        "uncertainty_flags": [],
                        "pulse_severity": "Informational",
                        "pulse_count": 0,
                    },
                    {
                        "ip": "8.8.8.8",
                        "fqdn": "dns.google",
                        "rdns": "dns.google",
                        "classification": "malicious",
                        "severity": "Critical",
                        "confidence": "A",
                        "evidence_flags": ["OTX:strong", "PULSE:volume"],
                        "uncertainty_flags": [],
                        "pulse_severity": "High",
                        "pulse_count": 12,
                    },
                ],
                "dns_lookups": {},
                "otx": None,
            }
            write_summary(model=model, summary_path=str(summary))
            out = summary.read_text(encoding="utf-8")
            self.assertIn("## Coldstep detect - IP classification", out)
            self.assertIn("### Decision banner", out)
            self.assertIn("Highest severity: 🟥 Critical", out)
            self.assertIn("Triage signal rows:", out)
            self.assertIn("Known infra rows:", out)
            self.assertIn("| 1.1.1.1 | one.one.one.one | one.one.one.one | clean | Known Public Resolver | 🟩 Low | B | OTX:clean | 🟩 Informational | 0 |", out)
            self.assertIn("| 8.8.8.8 | dns.google | dns.google | malicious | Known Public Resolver | 🟥 Critical | A | OTX:strong, PULSE:volume | 🟧 High | 12 |", out)
            self.assertIn("### Known infra snapshot", out)
            self.assertIn("`8.8.8.8 (dns.google)` pulse=12", out)
            self.assertIn("### OTX pulse chart", out)
            self.assertIn("| 🟧 High |", out)
            self.assertIn("#### Top pulse-backed destinations", out)
            self.assertIn("`8.8.8.8 (dns.google)`", out)
            self.assertIn("### Uncertainty and contradictions", out)
            self.assertIn("### Action queue", out)
            self.assertNotIn("Capabilities", out)

    def test_summary_renders_pulse_glyphs_for_quick_scan(self) -> None:
        model = {
            "ip_classification": [
                {
                    "ip": "8.8.8.8",
                    "fqdn": "dns.google",
                    "rdns": "dns.google",
                    "classification": "malicious",
                    "severity": "Critical",
                    "confidence": "A",
                    "evidence_flags": ["OTX:strong"],
                    "uncertainty_flags": [],
                    "pulse_severity": "Critical",
                    "pulse_count": 20,
                },
                {
                    "ip": "1.1.1.1",
                    "fqdn": "one.one.one.one",
                    "rdns": "one.one.one.one",
                    "classification": "clean",
                    "severity": "Informational",
                    "confidence": "B",
                    "evidence_flags": ["OTX:clean"],
                    "uncertainty_flags": [],
                    "pulse_severity": "Informational",
                    "pulse_count": 0,
                },
            ],
            "dns_lookups": {},
            "otx": None,
        }
        out = render_markdown(model)
        self.assertIn("🟥 Critical", out)
        self.assertIn("🟩 Informational", out)

    def test_pulse_chart_handles_no_pulses(self) -> None:
        model = {
            "ip_classification": [
                {
                    "ip": "203.0.113.5",
                    "fqdn": "",
                    "rdns": "",
                    "classification": "unidentified",
                    "severity": "Informational",
                    "confidence": "C",
                    "evidence_flags": [],
                    "uncertainty_flags": [],
                    "pulse_severity": "Informational",
                    "pulse_count": 0,
                }
            ],
            "dns_lookups": {},
            "otx": None,
        }
        out = render_markdown(model)
        self.assertIn("### OTX pulse chart", out)
        self.assertIn("Total pulse count observed: 0", out)
        self.assertIn("No pulse-backed destinations in this run.", out)

    def test_summary_renders_dash_when_evidence_flags_empty(self) -> None:
        model = {
            "ip_classification": [
                {
                    "ip": "203.0.113.5",
                    "fqdn": "",
                    "rdns": "",
                    "classification": "unidentified",
                    "severity": "Informational",
                    "confidence": "C",
                    "evidence_flags": [],
                    "uncertainty_flags": [],
                    "pulse_severity": "Informational",
                    "pulse_count": 0,
                }
            ],
            "dns_lookups": {},
            "otx": None,
        }
        out = render_markdown(model)
        self.assertIn("| 203.0.113.5 |  |  | unidentified | External | 🟩 Informational | C | - | 🟩 Informational | 0 |", out)


if __name__ == "__main__":
    unittest.main()
