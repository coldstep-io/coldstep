import collections
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path


SCRIPT_PATH = Path(__file__).with_name("ci_coldstep_jsonl_traffic_diff.py")
SPEC = importlib.util.spec_from_file_location("coldstep_diff", SCRIPT_PATH)
MOD = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MOD)


class DiffScriptTests(unittest.TestCase):
    def test_load_events_counts_invalid_json_lines(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "events.jsonl"
            p.write_text('{"type":"tcp"}\nnot-json\n{"type":"udp"}\n', encoding="utf-8")
            events, invalid, _lines = MOD.load_events(str(p))
            self.assertEqual(2, len(events))
            self.assertEqual(1, invalid)

    def test_load_events_counts_non_empty_lines(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "events.jsonl"
            p.write_text('{"type":"tcp"}\n\nnot-json\n', encoding="utf-8")
            events, invalid, nlines = MOD.load_events(str(p))
            self.assertEqual(1, len(events))
            self.assertEqual(1, invalid)
            self.assertEqual(2, nlines)

    def test_http_fingerprint_retains_entropy_for_long_paths(self):
        prefix = "/api/v1/resource/" + ("a" * 120)
        ev1 = {"type": "http", "host": "example.test", "method": "GET", "path": prefix + "X"}
        ev2 = {"type": "http", "host": "example.test", "method": "GET", "path": prefix + "Y"}
        fp1 = MOD.traffic_fingerprint(ev1)
        fp2 = MOD.traffic_fingerprint(ev2)
        self.assertNotEqual(fp1, fp2)
        self.assertIn("h=", fp1)

    def test_count_fps_tracks_unclassified_event_types(self):
        events = [
            {"type": "tcp", "dst": "1.1.1.1", "dport": 443},
            {"type": "weird_event"},
            {"type": "weird_event"},
            {"foo": "bar"},
        ]
        _, _, unclassified = MOD.count_fps(events)
        self.assertEqual(2, unclassified["weird_event"])
        self.assertEqual(1, unclassified["<missing-type>"])

    def test_other_fingerprint_normalizes_volatile_exec_and_fs_fields(self):
        exec1 = {"type": "exec", "exe": "/usr/bin/curl", "comm": "curl"}
        exec2 = {"type": "exec", "exe": "/usr/bin/curl", "comm": "curl-renamed"}
        self.assertEqual(MOD.other_fingerprint(exec1), MOD.other_fingerprint(exec2))

        fs1 = {"type": "fs_event", "op": "create", "path": "/tmp/a/random-1.txt"}
        fs2 = {"type": "fs_event", "op": "create", "path": "/var/log/random-1.txt"}
        self.assertEqual(MOD.other_fingerprint(fs1), MOD.other_fingerprint(fs2))

    def test_main_marks_relaxed_policy_when_unavailable_and_non_strict(self):
        with tempfile.TemporaryDirectory() as td:
            summary = Path(td) / "summary.md"
            baseline = Path(td) / "base.jsonl"
            current = Path(td) / "cur.jsonl"
            baseline.write_text('{"type":"tcp"}\n', encoding="utf-8")
            current.write_text("not-json\n", encoding="utf-8")

            old = dict(os.environ)
            try:
                os.environ["NS_SUMMARY"] = str(summary)
                os.environ["NS_BASELINE"] = str(baseline)
                os.environ["NS_CURRENT"] = str(current)
                os.environ["NS_MARKER"] = "unit"
                os.environ["COLDSTEP_DIFF_STRICT"] = "0"
                rc = MOD.main()
            finally:
                os.environ.clear()
                os.environ.update(old)

            self.assertEqual(0, rc)
            text = summary.read_text(encoding="utf-8")
            self.assertIn("unit.result=unavailable", text)
            self.assertIn("unit.policy=relaxed", text)

    def test_main_fails_when_unavailable_and_strict(self):
        with tempfile.TemporaryDirectory() as td:
            summary = Path(td) / "summary.md"
            baseline = Path(td) / "base.jsonl"
            current = Path(td) / "cur.jsonl"
            baseline.write_text('{"type":"tcp"}\n', encoding="utf-8")
            current.write_text("not-json\n", encoding="utf-8")

            old = dict(os.environ)
            try:
                os.environ["NS_SUMMARY"] = str(summary)
                os.environ["NS_BASELINE"] = str(baseline)
                os.environ["NS_CURRENT"] = str(current)
                os.environ["NS_MARKER"] = "unit"
                os.environ["COLDSTEP_DIFF_STRICT"] = "1"
                rc = MOD.main()
            finally:
                os.environ.clear()
                os.environ.update(old)

            self.assertEqual(1, rc)
            text = summary.read_text(encoding="utf-8")
            self.assertIn("unit.result=unavailable", text)
            self.assertNotIn("unit.policy=relaxed", text)

    def test_main_strict_fails_when_diff_ok_but_parse_degraded(self):
        with tempfile.TemporaryDirectory() as td:
            summary = Path(td) / "summary.md"
            baseline = Path(td) / "base.jsonl"
            current = Path(td) / "cur.jsonl"
            baseline.write_text(
                '{"type":"tcp","dst":"1.1.1.1","dport":443}\nbad\n', encoding="utf-8"
            )
            current.write_text(
                '{"type":"tcp","dst":"1.1.1.1","dport":443}\nbad\n', encoding="utf-8"
            )

            old = dict(os.environ)
            try:
                os.environ["NS_SUMMARY"] = str(summary)
                os.environ["NS_BASELINE"] = str(baseline)
                os.environ["NS_CURRENT"] = str(current)
                os.environ["NS_MARKER"] = "unit"
                os.environ["COLDSTEP_DIFF_STRICT"] = "1"
                rc = MOD.main()
            finally:
                os.environ.clear()
                os.environ.update(old)

            self.assertEqual(1, rc)
            text = summary.read_text(encoding="utf-8")
            self.assertIn("unit.parse.health=degraded", text)

    def test_main_non_strict_ok_when_parse_degraded(self):
        with tempfile.TemporaryDirectory() as td:
            summary = Path(td) / "summary.md"
            baseline = Path(td) / "base.jsonl"
            current = Path(td) / "cur.jsonl"
            baseline.write_text(
                '{"type":"tcp","dst":"1.1.1.1","dport":443}\nbad\n', encoding="utf-8"
            )
            current.write_text(
                '{"type":"tcp","dst":"1.1.1.1","dport":443}\nbad\n', encoding="utf-8"
            )

            old = dict(os.environ)
            try:
                os.environ["NS_SUMMARY"] = str(summary)
                os.environ["NS_BASELINE"] = str(baseline)
                os.environ["NS_CURRENT"] = str(current)
                os.environ["NS_MARKER"] = "unit"
                os.environ["COLDSTEP_DIFF_STRICT"] = "0"
                rc = MOD.main()
            finally:
                os.environ.clear()
                os.environ.update(old)

            self.assertEqual(0, rc)
            text = summary.read_text(encoding="utf-8")
            self.assertIn("unit.parse.health=degraded", text)

    def test_multiset_diff_ordering_deterministic(self):
        # prev={a:1,b:2} curr={b:3,c:1} => new c, gone a, chg b (2->3)
        prev = collections.Counter({"b": 2, "a": 1})
        curr = collections.Counter({"b": 3, "c": 1})
        new, gone, chg = MOD.multiset_diff(prev, curr)
        self.assertEqual([(1, "c")], new)
        self.assertEqual([(1, "a")], gone)
        self.assertEqual([(2, 3, "b")], chg)

    def test_main_writes_unclassified_marker_totals_to_summary(self):
        """C-SR-03: workflow summary lists unclassified counts (unknown type buckets)."""
        with tempfile.TemporaryDirectory() as td:
            summary = Path(td) / "summary.md"
            baseline = Path(td) / "base.jsonl"
            current = Path(td) / "cur.jsonl"
            baseline.write_text(
                '{"type":"tcp","dst":"1.1.1.1","dport":443}\n', encoding="utf-8"
            )
            current.write_text(
                '{"type":"tcp","dst":"1.1.1.1","dport":443}\n{"type":"phantom_xyz"}\n',
                encoding="utf-8",
            )
            summary.touch()

            old = dict(os.environ)
            try:
                os.environ["NS_SUMMARY"] = str(summary)
                os.environ["NS_BASELINE"] = str(baseline)
                os.environ["NS_CURRENT"] = str(current)
                os.environ["NS_MARKER"] = "unit"
                os.environ["COLDSTEP_DIFF_STRICT"] = "0"
                rc = MOD.main()
            finally:
                os.environ.clear()
                os.environ.update(old)

            self.assertEqual(0, rc)
            text = summary.read_text(encoding="utf-8")
            self.assertIn("unit.unclassified.base_total=0", text)
            self.assertIn("unit.unclassified.current_total=1", text)
            self.assertIn("phantom_xyz", text)


if __name__ == "__main__":
    unittest.main()
