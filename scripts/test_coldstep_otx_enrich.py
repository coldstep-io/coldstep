import io
import json
import os
import tempfile
import unittest
from pathlib import Path

from scripts.coldstep_otx import enrich
from scripts.coldstep_otx.client import InvalidAPIKey


def _v2_model_with_indicators() -> dict:
    return {
        "schema_version": 2,
        "generated_at": "2026-04-18T17:00:00Z",
        "run": {"run_id": "test"},
        "capability_matrix": [],
        "events_by_type": [],
        "timeline": [],
        "egress_sankey": [
            {"source": "evil.example.com", "target": "allow", "value": 1,
             "indicators": ["evil.example.com"]},
            {"source": "8.8.8.8", "target": "allow", "value": 3,
             "indicators": ["8.8.8.8"]},
        ],
        "diff": {
            "status": "ok",
            "traffic_new": [{"count": 1, "fingerprint": "x",
                             "indicators": ["evil.example.com", "1.2.3.4"]}],
            "traffic_gone": [],
            "traffic_changed": [],
        },
        "otx": None,
    }


class _FakeClient:
    def __init__(self, table):
        self._table = table
        self.calls = []

    def get_general(self, indicator_type, indicator):
        self.calls.append((indicator_type, indicator))
        if indicator in self._table:
            v = self._table[indicator]
            if isinstance(v, Exception):
                raise v
            return v
        return None


FIX = Path(__file__).parent / "coldstep_otx" / "fixtures"


def _fix(name: str) -> dict:
    return json.loads((FIX / name).read_text(encoding="utf-8"))


class EnrichOrchestratorTests(unittest.TestCase):
    def _write_model(self, model: dict) -> str:
        tmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
        tmp.write(json.dumps(model))
        tmp.close()
        return tmp.name

    def test_skips_when_no_api_key(self):
        path = self._write_model(_v2_model_with_indicators())
        try:
            stderr = io.StringIO()
            rc = enrich.run(model_path=path, api_key="", client_factory=lambda k: None,
                            stderr=stderr, now_monotonic=lambda: 0.0, wall_budget_ms=30000)
            self.assertEqual(rc, 0)
            data = json.loads(Path(path).read_text(encoding="utf-8"))
            self.assertTrue(data["otx"]["skipped"])
            self.assertEqual(data["otx"]["skipped_reason"], "no api key")
            self.assertEqual(data["schema_version"], 2)
        finally:
            os.unlink(path)

    def test_classifies_all_indicators_and_summary_counts_match(self):
        evil = _fix("general-malicious.json")
        clean = _fix("general-clean.json")
        unidentified = _fix("general-unidentified.json")
        fake = _FakeClient({"evil.example.com": evil, "8.8.8.8": clean, "1.2.3.4": unidentified})
        path = self._write_model(_v2_model_with_indicators())
        try:
            stderr = io.StringIO()
            rc = enrich.run(model_path=path, api_key="k", client_factory=lambda k: fake,
                            stderr=stderr, now_monotonic=lambda: 0.0, wall_budget_ms=30000)
            self.assertEqual(rc, 0)
            data = json.loads(Path(path).read_text(encoding="utf-8"))
            self.assertFalse(data["otx"]["skipped"])
            self.assertEqual(data["otx"]["summary"],
                             {"malicious": 1, "clean": 1, "unidentified": 1, "total": 3})
            inds = {row["indicator"]: row for row in data["otx"]["indicators"]}
            self.assertEqual(inds["evil.example.com"]["verdict"], "malicious")
            self.assertEqual(inds["8.8.8.8"]["verdict"], "clean")
            self.assertEqual(inds["1.2.3.4"]["verdict"], "unidentified")
        finally:
            os.unlink(path)

    def test_emits_warning_for_malicious(self):
        evil = _fix("general-malicious.json")
        unidentified = _fix("general-unidentified.json")
        # 8.8.8.8 not in table -> get_general returns None (404 sentinel) -> unidentified.
        fake = _FakeClient({"evil.example.com": evil, "1.2.3.4": unidentified})
        path = self._write_model(_v2_model_with_indicators())
        try:
            stderr = io.StringIO()
            enrich.run(model_path=path, api_key="k", client_factory=lambda k: fake,
                       stderr=stderr, now_monotonic=lambda: 0.0, wall_budget_ms=30000)
            out = stderr.getvalue()
            self.assertIn("::warning", out)
            self.assertIn("evil.example.com", out)
            self.assertNotIn("8.8.8.8", out)
        finally:
            os.unlink(path)

    def test_partial_results_when_budget_exhausted(self):
        evil = _fix("general-malicious.json")
        clean = _fix("general-clean.json")
        unidentified = _fix("general-unidentified.json")
        fake = _FakeClient({"evil.example.com": evil, "8.8.8.8": clean, "1.2.3.4": unidentified})
        path = self._write_model(_v2_model_with_indicators())
        # Time jumps: 0s start, 0.1s after first check, 30.001s after second check (budget hit).
        ticks = iter([0.0, 0.1, 30.001, 30.002, 30.003, 30.004])
        try:
            enrich.run(model_path=path, api_key="k", client_factory=lambda k: fake,
                       stderr=io.StringIO(),
                       now_monotonic=lambda: next(ticks), wall_budget_ms=30000)
            data = json.loads(Path(path).read_text(encoding="utf-8"))
            self.assertTrue(data["otx"]["partial_results"])
            self.assertGreaterEqual(len(data["otx"]["indicators"]), 1)
            self.assertLess(len(data["otx"]["indicators"]), 3)
        finally:
            os.unlink(path)

    def test_handles_invalid_api_key_gracefully_at_factory(self):
        def bad_factory(k):
            raise InvalidAPIKey("403 from test")
        path = self._write_model(_v2_model_with_indicators())
        try:
            rc = enrich.run(model_path=path, api_key="bad", client_factory=bad_factory,
                            stderr=io.StringIO(), now_monotonic=lambda: 0.0, wall_budget_ms=30000)
            self.assertEqual(rc, 0)
            data = json.loads(Path(path).read_text(encoding="utf-8"))
            self.assertTrue(data["otx"]["skipped"])
            self.assertEqual(data["otx"]["skipped_reason"], "403 invalid api key")
        finally:
            os.unlink(path)

    def test_handles_invalid_api_key_during_get(self):
        fake = _FakeClient({"evil.example.com": InvalidAPIKey("403 mid-stream")})
        path = self._write_model(_v2_model_with_indicators())
        try:
            rc = enrich.run(model_path=path, api_key="k", client_factory=lambda k: fake,
                            stderr=io.StringIO(), now_monotonic=lambda: 0.0, wall_budget_ms=30000)
            self.assertEqual(rc, 0)
            data = json.loads(Path(path).read_text(encoding="utf-8"))
            self.assertTrue(data["otx"]["skipped"])
            self.assertEqual(data["otx"]["skipped_reason"], "403 invalid api key")
        finally:
            os.unlink(path)

    def test_indicators_sorted_malicious_first(self):
        evil = _fix("general-malicious.json")
        clean = _fix("general-clean.json")
        unidentified = _fix("general-unidentified.json")
        fake = _FakeClient({"evil.example.com": evil, "8.8.8.8": clean, "1.2.3.4": unidentified})
        path = self._write_model(_v2_model_with_indicators())
        try:
            enrich.run(model_path=path, api_key="k", client_factory=lambda k: fake,
                       stderr=io.StringIO(), now_monotonic=lambda: 0.0, wall_budget_ms=30000)
            data = json.loads(Path(path).read_text(encoding="utf-8"))
            verdicts = [row["verdict"] for row in data["otx"]["indicators"]]
            self.assertEqual(verdicts[0], "malicious")
            # malicious > unidentified > clean
            self.assertEqual(verdicts[-1], "clean")
        finally:
            os.unlink(path)

    def test_no_indicators_in_model_skips_cleanly(self):
        model = _v2_model_with_indicators()
        model["egress_sankey"] = []
        model["diff"] = {"status": "ok", "traffic_new": [], "traffic_gone": [], "traffic_changed": []}
        path = self._write_model(model)
        try:
            rc = enrich.run(model_path=path, api_key="k", client_factory=lambda k: _FakeClient({}),
                            stderr=io.StringIO(), now_monotonic=lambda: 0.0, wall_budget_ms=30000)
            self.assertEqual(rc, 0)
            data = json.loads(Path(path).read_text(encoding="utf-8"))
            self.assertTrue(data["otx"]["skipped"])
            self.assertEqual(data["otx"]["skipped_reason"], "no indicators in model")
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
