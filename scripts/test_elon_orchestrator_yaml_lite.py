import unittest
from scripts.elon_orchestrator import yaml_lite as YL


class YamlLiteParseTests(unittest.TestCase):

    def test_parses_simple_key_value_strings(self):
        data = YL.parse("kind: source-cache\nsource: https://example.com/x\n")
        self.assertEqual(data, {"kind": "source-cache", "source": "https://example.com/x"})

    def test_parses_inline_list(self):
        data = YL.parse("tags: [ietf, rfc, tls]\n")
        self.assertEqual(data, {"tags": ["ietf", "rfc", "tls"]})

    def test_parses_block_list(self):
        data = YL.parse("tags:\n  - ietf\n  - rfc\n  - tls\n")
        self.assertEqual(data, {"tags": ["ietf", "rfc", "tls"]})

    def test_parses_quoted_string_with_colon(self):
        data = YL.parse('record: "[[records/2026-04-19-rfc-791-ipv4]]"\n')
        self.assertEqual(data, {"record": "[[records/2026-04-19-rfc-791-ipv4]]"})

    def test_parses_iso_timestamp_value_unquoted(self):
        data = YL.parse("fetched_at: 2026-04-19T03:00:00Z\n")
        self.assertEqual(data, {"fetched_at": "2026-04-19T03:00:00Z"})

    def test_parses_unicode_value_round_trips_bytes(self):
        # \u00bb is the canonical fingerprint separator used in coldstep_detect_report.
        data = YL.parse('summary: "host \u00bb policy"\n')
        self.assertEqual(data["summary"], "host \u00bb policy")

    def test_parses_nested_dict_one_level(self):
        text = "defaults:\n  fp: 0.30\n  vi: 0.30\n  sh: 0.10\n  co: 0.30\n"
        data = YL.parse(text)
        self.assertEqual(data, {"defaults": {"fp": "0.30", "vi": "0.30", "sh": "0.10", "co": "0.30"}})

    def test_ignores_blank_lines_and_comments(self):
        text = "# a comment\nkind: report\n\n# another\ntags: [x]\n"
        data = YL.parse(text)
        self.assertEqual(data, {"kind": "report", "tags": ["x"]})


class YamlLiteSerializeTests(unittest.TestCase):

    def test_round_trip_preserves_field_order(self):
        original = {"kind": "raw-stub", "source": "https://x/y", "tags": ["a", "b"]}
        text = YL.dump(original)
        roundtrip = YL.parse(text)
        self.assertEqual(roundtrip, original)
        self.assertLess(text.index("kind:"), text.index("source:"))
        self.assertLess(text.index("source:"), text.index("tags:"))

    def test_round_trip_preserves_unicode(self):
        original = {"summary": "host \u00bb policy \u2192 verdict"}
        text = YL.dump(original)
        self.assertIn("\u00bb", text)
        self.assertEqual(YL.parse(text), original)

    def test_serializes_inline_list_for_short_lists(self):
        text = YL.dump({"tags": ["a", "b", "c"]})
        self.assertIn("tags: [a, b, c]", text)

    def test_serializes_block_list_for_long_lists(self):
        text = YL.dump({"tags": ["a", "b", "c", "d", "e", "f", "g", "h"]})
        self.assertIn("tags:\n  - a\n  - b\n", text)


if __name__ == "__main__":
    unittest.main()
