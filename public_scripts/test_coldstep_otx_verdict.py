import json
import unittest
from pathlib import Path

from public_scripts.coldstep_otx.verdict import classify

FIX = Path(__file__).parent / "coldstep_otx" / "fixtures"


def _load(name: str) -> dict:
    return json.loads((FIX / name).read_text(encoding="utf-8"))


class ClassifyTests(unittest.TestCase):
    def test_clean_when_validation_present_even_if_pulses(self):
        # Whitelisted infra wins even if a pulse mentions the indicator
        # (matches upstream is_malicious.py).
        data = _load("general-clean.json")
        verdict, evidence = classify(data)
        self.assertEqual(verdict, "clean")
        self.assertEqual(evidence, [])

    def test_malicious_when_pulses_and_no_validation(self):
        data = _load("general-malicious.json")
        verdict, evidence = classify(data)
        self.assertEqual(verdict, "malicious")
        self.assertEqual(len(evidence), 2)
        self.assertEqual(evidence[0]["pulse_id"], "62a1f0aaaaaaaaaaaaaaaaaa")
        self.assertEqual(evidence[0]["pulse_name"], "Lazarus Q2 IOCs")
        self.assertIn("AppleJeus", evidence[0]["malware_families"])
        self.assertIn("T1071.001", evidence[0]["attack_ids"])

    def test_evidence_sorted_by_modified_desc(self):
        data = _load("general-malicious.json")
        _, evidence = classify(data)
        self.assertEqual(evidence[0]["modified"], "2026-04-15T10:11:12.000")
        self.assertEqual(evidence[1]["modified"], "2025-09-01T00:00:00.000")

    def test_evidence_capped_at_five(self):
        data = _load("general-malicious.json")
        base = data["pulse_info"]["pulses"][0]
        data["pulse_info"]["pulses"] = [
            {**base, "id": f"p{i:024d}", "modified": f"2026-04-1{i}T00:00:00.000"}
            for i in range(8)
        ]
        data["pulse_info"]["count"] = 8
        _, evidence = classify(data)
        self.assertEqual(len(evidence), 5)

    def test_unidentified_when_empty(self):
        data = _load("general-unidentified.json")
        verdict, evidence = classify(data)
        self.assertEqual(verdict, "unidentified")
        self.assertEqual(evidence, [])

    def test_unidentified_on_None(self):
        verdict, evidence = classify(None)
        self.assertEqual(verdict, "unidentified")
        self.assertEqual(evidence, [])

    def test_unidentified_on_garbage_shape(self):
        verdict, evidence = classify({"unexpected": True})
        self.assertEqual(verdict, "unidentified")
        self.assertEqual(evidence, [])


if __name__ == "__main__":
    unittest.main()
