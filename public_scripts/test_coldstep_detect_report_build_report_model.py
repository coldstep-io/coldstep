import datetime as dt
import tempfile
import unittest
from pathlib import Path

from public_scripts.coldstep_detect_report.build_report_model import build


class BuildReportModelTests(unittest.TestCase):
    def test_includes_ip_classification_from_same_jsonl(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            jsonl = Path(td) / "events.jsonl"
            jsonl.write_text(
                '{"type":"tcp","dst":"8.8.8.8","fqdn":"dns.google"}\n',
                encoding="utf-8",
            )
            model = build(
                current_jsonl=str(jsonl),
                baseline_jsonl=None,
                now=dt.datetime(2026, 4, 20, tzinfo=dt.timezone.utc),
            )
            self.assertEqual(model["schema_version"], "2.2")
            rows = model.get("ip_classification") or []
            self.assertTrue(rows)
            self.assertEqual(rows[0]["ip"], "8.8.8.8")


if __name__ == "__main__":
    unittest.main()
