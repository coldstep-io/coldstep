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

    def test_unexpected_client_exception_is_caught_per_indicator(self):
        # Defense-in-depth: if the client throws an exception that isn't an
        # OTXError subclass (e.g. a raw TimeoutError that escaped a buggy
        # client, or any future regression), the orchestrator must NOT crash —
        # it must mark that indicator as unidentified, keep going, and exit 0.
        # Regressed in CI run 24618444911 where a TimeoutError from urllib
        # killed the whole step.
        fake = _FakeClient({
            "evil.example.com": _fix("general-malicious.json"),
            "8.8.8.8": TimeoutError("read timeout"),
            "1.2.3.4": _fix("general-unidentified.json"),
        })
        path = self._write_model(_v2_model_with_indicators())
        try:
            rc = enrich.run(model_path=path, api_key="k", client_factory=lambda k: fake,
                            stderr=io.StringIO(), now_monotonic=lambda: 0.0, wall_budget_ms=30000)
            self.assertEqual(rc, 0)
            data = json.loads(Path(path).read_text(encoding="utf-8"))
            self.assertFalse(data["otx"]["skipped"])
            inds = {row["indicator"]: row for row in data["otx"]["indicators"]}
            self.assertEqual(inds["evil.example.com"]["verdict"], "malicious")
            self.assertEqual(inds["8.8.8.8"]["verdict"], "unidentified")
            self.assertIn("note", inds["8.8.8.8"])
            self.assertEqual(inds["1.2.3.4"]["verdict"], "unidentified")
        finally:
            os.unlink(path)

    def test_warning_encodes_pulse_name_workflow_command_chars(self):
        # GitHub Actions workflow commands are line-oriented: an OTX pulse name
        # containing newlines or '%' could inject a second '::error::' command
        # downstream. Encode per
        # https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions
        evil = {
            "pulse_info": {
                "count": 1,
                "pulses": [{
                    "id": "p1",
                    "name": "naughty\n::error::pwned",
                    "modified": "2026-04-18T00:00:00",
                    "malware_families": [{"display_name": "100% bad"}],
                }],
            },
        }
        fake = _FakeClient({"evil.example.com": evil})
        path = self._write_model(_v2_model_with_indicators())
        try:
            stderr = io.StringIO()
            enrich.run(model_path=path, api_key="k", client_factory=lambda k: fake,
                       stderr=stderr, now_monotonic=lambda: 0.0, wall_budget_ms=30000)
            out = stderr.getvalue()
            self.assertIn("%0A", out)
            self.assertNotIn("\n::error::pwned", out)
            self.assertIn("100%25 bad", out)
        finally:
            os.unlink(path)

    def test_main_returns_zero_on_corrupt_model_json(self):
        # The orchestrator's docstring promises "Always returns 0" - that has to
        # cover load failures too, not just per-indicator client failures.
        tmp = tempfile.NamedTemporaryFile("wb", suffix=".json", delete=False)
        tmp.write(b"{not valid json")
        tmp.close()
        old_env = {k: os.environ.get(k) for k in
                   ("COLDSTEP_REPORT_MODEL_IN", "OTX_API_KEY", "COLDSTEP_OTX_WALL_BUDGET_MS")}
        try:
            os.environ["COLDSTEP_REPORT_MODEL_IN"] = tmp.name
            os.environ["OTX_API_KEY"] = ""
            os.environ.pop("COLDSTEP_OTX_WALL_BUDGET_MS", None)
            self.assertEqual(enrich.main(), 0)
        finally:
            for k, v in old_env.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
            os.unlink(tmp.name)

    def test_main_returns_zero_on_unparseable_budget_env_var(self):
        path = self._write_model(_v2_model_with_indicators())
        old_env = {k: os.environ.get(k) for k in
                   ("COLDSTEP_REPORT_MODEL_IN", "OTX_API_KEY", "COLDSTEP_OTX_WALL_BUDGET_MS")}
        try:
            os.environ["COLDSTEP_REPORT_MODEL_IN"] = path
            os.environ["OTX_API_KEY"] = ""
            os.environ["COLDSTEP_OTX_WALL_BUDGET_MS"] = "not-a-number"
            self.assertEqual(enrich.main(), 0)
        finally:
            for k, v in old_env.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
            os.unlink(path)

    def test_loopback_indicator_skips_otx_and_is_logged_as_clean(self):
        # 127.0.0.0/8 is loopback by RFC 5735. Sending it to OTX would burn an
        # API call for a guaranteed-404 - and worse, an OTX-returned
        # "unidentified" verdict would make a benign local probe look suspect
        # in the report. Allowlist short-circuits the call but the indicator
        # MUST still appear in indicators[] (auditable).
        model = _v2_model_with_indicators()
        model["egress_sankey"].append(
            {"source": "127.0.0.1", "target": "allow", "value": 1, "indicators": ["127.0.0.1"]}
        )
        evil = _fix("general-malicious.json")
        fake = _FakeClient({"evil.example.com": evil})  # 8.8.8.8 + 1.2.3.4 + 127.0.0.1 not in table
        path = self._write_model(model)
        try:
            enrich.run(model_path=path, api_key="k", client_factory=lambda k: fake,
                       stderr=io.StringIO(), now_monotonic=lambda: 0.0, wall_budget_ms=30000)
            data = json.loads(Path(path).read_text(encoding="utf-8"))
            inds = {row["indicator"]: row for row in data["otx"]["indicators"]}
            self.assertIn("127.0.0.1", inds)
            self.assertEqual(inds["127.0.0.1"]["verdict"], "clean")
            self.assertEqual(inds["127.0.0.1"]["source"], "allowlist")
            self.assertEqual(inds["127.0.0.1"]["reason"], "loopback")
            self.assertNotIn(("IPv4", "127.0.0.1"), fake.calls)
            self.assertEqual(data["otx"]["allowlisted"], 1)
        finally:
            os.unlink(path)

    def test_loopback_indicator_does_not_consume_api_calls(self):
        model = _v2_model_with_indicators()
        model["egress_sankey"] = [
            {"source": "127.0.0.1", "target": "allow", "value": 1, "indicators": ["127.0.0.1"]},
            {"source": "127.99.0.7", "target": "allow", "value": 1, "indicators": ["127.99.0.7"]},
        ]
        model["diff"] = {"status": "ok", "traffic_new": [], "traffic_gone": [], "traffic_changed": []}
        fake = _FakeClient({})
        path = self._write_model(model)
        try:
            enrich.run(model_path=path, api_key="k", client_factory=lambda k: fake,
                       stderr=io.StringIO(), now_monotonic=lambda: 0.0, wall_budget_ms=30000)
            data = json.loads(Path(path).read_text(encoding="utf-8"))
            self.assertEqual(fake.calls, [])
            self.assertEqual(data["otx"]["api_calls"], 0)
            self.assertEqual(data["otx"]["allowlisted"], 2)
            self.assertEqual(data["otx"]["summary"]["clean"], 2)
            self.assertEqual(data["otx"]["summary"]["total"], 2)
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


class EnrichSanitizationParityTests(unittest.TestCase):
    """F-P2-01: enrich.py must accept paths under the same trusted-root set as
    scripts/coldstep_detect_report/build_report_model.py — workspace, runner
    temp, system temp, and (when no workspace) cwd. AGENTS.md canonical helper.
    """

    def _write_model(self, dir_path: Path) -> Path:
        p = dir_path / "report-model.json"
        p.write_text(json.dumps({"schema_version": 2}), encoding="utf-8")
        return p

    def test_accepts_path_under_runner_temp(self):
        with tempfile.TemporaryDirectory() as runner_temp:
            old_runner = os.environ.pop("RUNNER_TEMP", None)
            old_workspace = os.environ.pop("GITHUB_WORKSPACE", None)
            os.environ["RUNNER_TEMP"] = runner_temp
            try:
                model_path = self._write_model(Path(runner_temp))
                resolved = enrich._safe_workspace_path(
                    str(model_path), var_name="COLDSTEP_REPORT_MODEL_IN"
                )
                self.assertEqual(os.path.realpath(str(model_path)), resolved)
            finally:
                if old_runner is not None:
                    os.environ["RUNNER_TEMP"] = old_runner
                else:
                    os.environ.pop("RUNNER_TEMP", None)
                if old_workspace is not None:
                    os.environ["GITHUB_WORKSPACE"] = old_workspace

    def test_accepts_path_under_system_tempdir(self):
        with tempfile.TemporaryDirectory() as td:
            old_workspace = os.environ.pop("GITHUB_WORKSPACE", None)
            old_runner = os.environ.pop("RUNNER_TEMP", None)
            try:
                model_path = self._write_model(Path(td))
                resolved = enrich._safe_workspace_path(
                    str(model_path), var_name="COLDSTEP_REPORT_MODEL_IN"
                )
                self.assertEqual(os.path.realpath(str(model_path)), resolved)
            finally:
                if old_workspace is not None:
                    os.environ["GITHUB_WORKSPACE"] = old_workspace
                if old_runner is not None:
                    os.environ["RUNNER_TEMP"] = old_runner

    def test_rejects_disallowed_chars(self):
        with self.assertRaises(ValueError):
            enrich._safe_workspace_path("/etc/passwd; rm -rf /", var_name="TEST")


if __name__ == "__main__":
    unittest.main()
