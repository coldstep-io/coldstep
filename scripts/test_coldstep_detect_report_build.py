import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path


PKG_DIR = Path(__file__).with_name("coldstep_detect_report")
BUILD = PKG_DIR / "build_report_model.py"
SPEC = importlib.util.spec_from_file_location("crd_build", BUILD)
MOD = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MOD)

CURR = PKG_DIR / "fixtures" / "coldstep-events.sample.jsonl"
BASE = PKG_DIR / "fixtures" / "baseline-events.sample.jsonl"


class BuildReportModelTests(unittest.TestCase):
    def test_model_has_required_top_level_keys(self):
        model = MOD.build(current_jsonl=str(CURR), baseline_jsonl=str(BASE))
        for k in ("schema_version", "generated_at", "run", "capability_matrix",
                  "events_by_type", "timeline", "egress_sankey", "diff"):
            self.assertIn(k, model, f"missing key: {k}")
        self.assertEqual(model["schema_version"], 1)

    def test_capability_matrix_marks_each_required_capability_pass(self):
        model = MOD.build(current_jsonl=str(CURR), baseline_jsonl=str(BASE))
        rows = {row["id"]: row for row in model["capability_matrix"]}
        for cap in ("exec", "tcp", "udp", "http", "tls", "proc_fork", "fs_event"):
            self.assertEqual(rows[cap]["status"], "pass", f"{cap} should pass on the sample")

    def test_events_by_type_counts_match_jsonl(self):
        model = MOD.build(current_jsonl=str(CURR), baseline_jsonl=str(BASE))
        counts = {row["type"]: row["count"] for row in model["events_by_type"]}
        self.assertEqual(counts["fs_event"], 4)
        self.assertEqual(counts["tcp"], 1)
        self.assertEqual(counts["http"], 1)

    def test_diff_lists_missing_traffic_fingerprint_for_removed_host(self):
        model = MOD.build(current_jsonl=str(CURR), baseline_jsonl=str(BASE))
        gone = [row["fingerprint"] for row in model["diff"]["traffic_gone"]]
        self.assertTrue(any("theclouddj.com" in fp for fp in gone),
                        f"expected theclouddj.com in traffic_gone, got {gone}")

    def test_egress_sankey_aggregates_by_host_and_policy(self):
        model = MOD.build(current_jsonl=str(CURR), baseline_jsonl=str(BASE))
        edges = model["egress_sankey"]
        self.assertTrue(any(e["source"] == "example.com" and e["target"] == "allow" for e in edges))

    def test_build_works_without_baseline(self):
        model = MOD.build(current_jsonl=str(CURR), baseline_jsonl=None)
        self.assertEqual(model["diff"]["status"], "unavailable")
        self.assertEqual(model["diff"]["reason"], "no_baseline_provided")

    def test_timeline_emits_utc_buckets_with_z_suffix(self):
        model = MOD.build(current_jsonl=str(CURR), baseline_jsonl=str(BASE))
        timeline = model["timeline"]
        self.assertGreater(len(timeline), 0)
        for row in timeline:
            self.assertTrue(row["bucket"].endswith("Z"), f"non-UTC bucket: {row['bucket']!r}")
            self.assertGreaterEqual(row["count"], 1)

    def test_load_jsonl_skips_garbage_lines_silently(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "mixed.jsonl"
            p.write_text(
                '{"type":"tcp","ts":"2026-04-18T17:00:00Z","dst":"1.1.1.1","dport":443,"policy":"allow"}\n'
                'this is not json\n'
                '\n'
                '{"type":"udp","ts":"2026-04-18T17:00:01Z","dst":"8.8.8.8","dport":53,"policy":"allow"}\n',
                encoding="utf-8",
            )
            model = MOD.build(current_jsonl=str(p), baseline_jsonl=None)
            counts = {row["type"]: row["count"] for row in model["events_by_type"]}
            self.assertEqual(counts.get("tcp"), 1)
            self.assertEqual(counts.get("udp"), 1)

    def test_run_run_id_falls_back_to_env_when_no_meta_event(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "no-meta.jsonl"
            p.write_text(
                '{"type":"exec","ts":"2026-04-18T17:00:00Z","exe":"/bin/true","comm":"true","pid":1}\n',
                encoding="utf-8",
            )
            old = os.environ.get("GITHUB_RUN_ID")
            os.environ["GITHUB_RUN_ID"] = "env-run-id-42"
            try:
                model = MOD.build(current_jsonl=str(p), baseline_jsonl=None)
            finally:
                if old is None:
                    os.environ.pop("GITHUB_RUN_ID", None)
                else:
                    os.environ["GITHUB_RUN_ID"] = old
            self.assertEqual(model["run"]["run_id"], "env-run-id-42")


if __name__ == "__main__":
    unittest.main()
