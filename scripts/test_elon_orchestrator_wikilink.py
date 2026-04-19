import tempfile
import unittest
from pathlib import Path

from scripts.elon_orchestrator import wikilink as WL


class ResolveWikilinkTests(unittest.TestCase):

    def setUp(self):
        self.vault = Path(tempfile.mkdtemp())
        for sub in ("records", "raw", "wiki", "reports"):
            (self.vault / sub).mkdir()

    def test_resolves_wiki_hub_with_md_extension(self):
        target = self.vault / "wiki" / "ietf-rfcs.md"
        target.write_text("# IETF\n", encoding="utf-8")
        self.assertEqual(WL.resolve("wiki/ietf-rfcs", self.vault), target)
        self.assertEqual(WL.resolve("wiki/ietf-rfcs.md", self.vault), target)

    def test_resolves_record_dated_slug(self):
        target = self.vault / "records" / "2026-04-19-rfc-791-ipv4.md"
        target.write_text("# RFC 791\n", encoding="utf-8")
        self.assertEqual(WL.resolve("records/2026-04-19-rfc-791-ipv4", self.vault), target)

    def test_resolves_raw_stub(self):
        target = self.vault / "raw" / "2026-04-19-rfc-9000-quic.md"
        target.write_text("# QUIC\n", encoding="utf-8")
        self.assertEqual(WL.resolve("raw/2026-04-19-rfc-9000-quic", self.vault), target)

    def test_resolves_report(self):
        target = self.vault / "reports" / "2026-04-16-bugfix-policy.md"
        target.write_text("# Policy\n", encoding="utf-8")
        self.assertEqual(WL.resolve("reports/2026-04-16-bugfix-policy", self.vault), target)

    def test_strips_brackets_from_target(self):
        target = self.vault / "wiki" / "x.md"
        target.write_text("x", encoding="utf-8")
        self.assertEqual(WL.resolve("[[wiki/x]]", self.vault), target)
        self.assertEqual(WL.resolve("[[wiki/x|alias]]", self.vault), target)

    def test_returns_None_when_target_does_not_exist(self):
        self.assertIsNone(WL.resolve("wiki/does-not-exist", self.vault))

    def test_returns_None_for_target_outside_known_buckets(self):
        # Refuse to resolve targets that don't live under records/raw/wiki/reports —
        # those shouldn't be wikilinked from inside the brain.
        (self.vault / "elsewhere").mkdir()
        (self.vault / "elsewhere" / "x.md").write_text("x", encoding="utf-8")
        self.assertIsNone(WL.resolve("elsewhere/x", self.vault))


if __name__ == "__main__":
    unittest.main()
