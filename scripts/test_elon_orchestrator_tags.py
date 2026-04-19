import tempfile
import unittest
from pathlib import Path

from scripts.elon_orchestrator import tags as T


class LoadTagAllowlistTests(unittest.TestCase):

    def setUp(self):
        self.vault = Path(tempfile.mkdtemp())
        (self.vault / ".elon").mkdir()

    def _write_allowlist(self, body: str) -> None:
        (self.vault / ".elon" / "tags.yml").write_text(body, encoding="utf-8")

    def test_loads_simple_flat_allowlist(self):
        self._write_allowlist("ietf: IETF RFCs and drafts\nrfc: a published RFC\ntls: TLS 1.2 / 1.3\n")
        allow = T.load_tag_allowlist(self.vault)
        self.assertEqual(allow, {"ietf": "IETF RFCs and drafts", "rfc": "a published RFC", "tls": "TLS 1.2 / 1.3"})

    def test_returns_empty_dict_when_file_missing(self):
        self.assertEqual(T.load_tag_allowlist(self.vault), {})


class ValidateTagTests(unittest.TestCase):

    def setUp(self):
        self.vault = Path(tempfile.mkdtemp())
        (self.vault / ".elon").mkdir()
        (self.vault / ".elon" / "tags.yml").write_text(
            "ietf: IETF\nrfc: an RFC\ntls: TLS\nipv4: IPv4\nbpf: BPF\n",
            encoding="utf-8",
        )

    def test_allowed_tag_returns_true_no_suggestions(self):
        ok, suggestions = T.validate_tag("ietf", self.vault)
        self.assertTrue(ok)
        self.assertEqual(suggestions, [])

    def test_unallowed_tag_returns_false_with_close_suggestions(self):
        ok, suggestions = T.validate_tag("itef", self.vault)
        self.assertFalse(ok)
        self.assertIn("ietf", suggestions)

    def test_unallowed_tag_with_no_close_matches_returns_empty_suggestions(self):
        ok, suggestions = T.validate_tag("totally-unrelated-tag-xyz", self.vault)
        self.assertFalse(ok)
        self.assertEqual(suggestions, [])

    def test_empty_allowlist_treats_every_tag_as_unknown(self):
        empty_vault = Path(tempfile.mkdtemp())
        ok, suggestions = T.validate_tag("anything", empty_vault)
        self.assertFalse(ok)
        self.assertEqual(suggestions, [])


if __name__ == "__main__":
    unittest.main()
