import datetime as dt
import tempfile
import unittest
from pathlib import Path

from scripts.coldstep_detect_report.build_ip_classification_model import (
    build,
    project_otx_classification,
)


class BuildIPClassificationModelTests(unittest.TestCase):
    def test_build_dedupes_ipv4_and_keeps_fqdn_hint(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            jsonl = Path(td) / "events.jsonl"
            jsonl.write_text(
                '{"type":"tcp","dst":"8.8.8.8","fqdn":"dns.google"}\n'
                '{"type":"udp","dst":"8.8.8.8"}\n'
                '{"type":"http","dst":"1.1.1.1","host":"one.one.one.one"}\n'
                '{"type":"tls","dst":"example.com"}\n',
                encoding="utf-8",
            )
            model = build(current_jsonl=str(jsonl), now=dt.datetime(2026, 4, 20, tzinfo=dt.timezone.utc))
            rows = model["ip_classification"]
            self.assertEqual([row["ip"] for row in rows], ["1.1.1.1", "8.8.8.8"])
            self.assertEqual(rows[0]["fqdn"], "one.one.one.one")
            self.assertEqual(rows[1]["fqdn"], "dns.google")
            self.assertEqual(rows[0]["rdns"], "")
            self.assertEqual(rows[0]["classification"], "unidentified")

    def test_projects_otx_verdict_and_pulse_and_rdns(self) -> None:
        model = {
            "ip_classification": [
                {
                    "ip": "8.8.8.8",
                    "fqdn": "dns.google",
                    "rdns": "",
                    "classification": "unidentified",
                    "pulse_severity": "Informational",
                    "pulse_count": 0,
                }
            ],
            "dns_lookups": {"8.8.8.8": "dns.google"},
            "otx": {
                "indicators": [
                    {
                        "indicator": "8.8.8.8",
                        "verdict": "malicious",
                        "pulse_severity": "Critical",
                        "pulse_count": 48,
                    }
                ]
            },
        }
        projected = project_otx_classification(model)
        row = projected["ip_classification"][0]
        self.assertEqual(row["classification"], "malicious")
        self.assertEqual(row["pulse_severity"], "Critical")
        self.assertEqual(row["pulse_count"], 48)
        self.assertEqual(row["rdns"], "dns.google")
        self.assertEqual(row["severity"], "Critical")
        self.assertEqual(row["confidence"], "A")
        self.assertIn("OTX:strong", row["evidence_flags"])
        self.assertEqual(row["uncertainty_flags"], [])

    def test_critical_gate_downgrades_when_not_corroborated(self) -> None:
        model = {
            "ip_classification": [
                {
                    "ip": "198.51.100.20",
                    "fqdn": "",
                    "rdns": "",
                    "classification": "unidentified",
                    "pulse_severity": "Informational",
                    "pulse_count": 0,
                }
            ],
            "dns_lookups": {},
            "otx": {
                "indicators": [
                    {
                        "indicator": "198.51.100.20",
                        "verdict": "malicious",
                        "pulse_severity": "Critical",
                        "pulse_count": 0,
                        "confidence": "low",
                    }
                ]
            },
        }
        projected = project_otx_classification(model)
        row = projected["ip_classification"][0]
        self.assertEqual(row["severity"], "High")
        self.assertIn("critical-gate-downgrade", row["uncertainty_flags"])


if __name__ == "__main__":
    unittest.main()
