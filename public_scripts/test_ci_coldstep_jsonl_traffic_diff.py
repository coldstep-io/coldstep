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

    def test_main_minimal_skips_fingerprint_tables(self):
        """Tier-1 job summary uses compact counts; full fingerprint tables are HTML-only."""
        with tempfile.TemporaryDirectory() as td:
            summary = Path(td) / "summary.md"
            baseline = Path(td) / "base.jsonl"
            current = Path(td) / "cur.jsonl"
            baseline.write_text(
                '{"type":"tcp","dst":"1.1.1.1","dport":443}\n', encoding="utf-8"
            )
            current.write_text(
                '{"type":"tcp","dst":"8.8.8.8","dport":443}\n', encoding="utf-8"
            )
            summary.touch()

            old = dict(os.environ)
            try:
                os.environ["NS_SUMMARY"] = str(summary)
                os.environ["NS_BASELINE"] = str(baseline)
                os.environ["NS_CURRENT"] = str(current)
                os.environ["NS_MARKER"] = "unit"
                os.environ["COLDSTEP_DIFF_STRICT"] = "0"
                os.environ["COLDSTEP_TRAFFIC_DIFF_SUMMARY"] = "minimal"
                rc = MOD.main()
            finally:
                os.environ.clear()
                os.environ.update(old)

            self.assertEqual(0, rc)
            text = summary.read_text(encoding="utf-8")
            self.assertIn("Previous-run traffic diff (compact)", text)
            self.assertIn("unit.result=changed", text)
            self.assertNotIn("New traffic (present in current", text)
            self.assertNotIn("traffic » tcp", text)

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


class TrafficIndicatorsTests(unittest.TestCase):
    def test_tls_event_with_dst_and_sni(self):
        ev = {"type": "tls", "dst": "93.184.216.34", "dport": 443, "sni": "example.com", "policy": "allow"}
        self.assertEqual(set(MOD.traffic_indicators(ev)), {"93.184.216.34", "example.com"})

    def test_http_event_with_dst_and_host(self):
        ev = {"type": "http", "dst": "1.1.1.1", "dport": 80, "host": "example.com", "method": "GET"}
        self.assertEqual(set(MOD.traffic_indicators(ev)), {"1.1.1.1", "example.com"})

    def test_tcp_event_with_dst_and_fqdn(self):
        ev = {"type": "tcp", "dst": "8.8.8.8", "dport": 53, "fqdn": "dns.google"}
        self.assertEqual(set(MOD.traffic_indicators(ev)), {"8.8.8.8", "dns.google"})

    def test_udp_event_dst_only_when_no_fqdn(self):
        ev = {"type": "udp", "dst": "8.8.8.8", "dport": 53}
        self.assertEqual(MOD.traffic_indicators(ev), ["8.8.8.8"])

    def test_filters_zero_address(self):
        ev = {"type": "tcp", "dst": "0.0.0.0", "dport": 0, "fqdn": ""}
        self.assertEqual(MOD.traffic_indicators(ev), [])

    def test_filters_empty_strings(self):
        ev = {"type": "tls", "dst": "", "dport": 443, "sni": ""}
        self.assertEqual(MOD.traffic_indicators(ev), [])

    def test_returns_empty_for_non_traffic_event(self):
        ev = {"type": "exec", "exe": "/bin/true"}
        self.assertEqual(MOD.traffic_indicators(ev), [])


if __name__ == "__main__":
    unittest.main()
