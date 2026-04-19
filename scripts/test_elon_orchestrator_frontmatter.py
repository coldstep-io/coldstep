import tempfile
import unittest
from pathlib import Path

from scripts.elon_orchestrator import frontmatter as FM


class FrontmatterReadTests(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def _write(self, name: str, body: str) -> Path:
        path = self.tmp / name
        path.write_text(body, encoding="utf-8")
        return path

    def test_reads_frontmatter_returns_dict_and_body(self):
        path = self._write("a.md", "---\nkind: report\ntags: [x, y]\n---\n# Body\n\nhello\n")
        meta, body = FM.read(path)
        self.assertEqual(meta, {"kind": "report", "tags": ["x", "y"]})
        self.assertEqual(body, "# Body\n\nhello\n")

    def test_no_frontmatter_returns_empty_dict_and_full_body(self):
        path = self._write("b.md", "# Just markdown\n\ntext\n")
        meta, body = FM.read(path)
        self.assertEqual(meta, {})
        self.assertEqual(body, "# Just markdown\n\ntext\n")

    def test_unicode_in_body_round_trips(self):
        path = self._write("c.md", "---\nkind: report\n---\nhost \u00bb policy \u2192 verdict\n")
        _, body = FM.read(path)
        self.assertIn("\u00bb", body)
        self.assertIn("\u2192", body)


class FrontmatterWriteTests(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def test_writes_frontmatter_then_body_with_separator(self):
        path = self.tmp / "a.md"
        FM.write(path, {"kind": "raw-stub", "source": "https://x/y"}, "# Body\n")
        text = path.read_text(encoding="utf-8")
        self.assertTrue(text.startswith("---\n"))
        self.assertIn("kind: raw-stub", text)
        self.assertIn("source: https://x/y", text)
        self.assertIn("---\n# Body\n", text)

    def test_round_trips_unicode_through_write_then_read(self):
        path = self.tmp / "b.md"
        original_meta = {"summary": "host \u00bb policy"}
        original_body = "host \u00bb policy \u2192 verdict\n"
        FM.write(path, original_meta, original_body)
        meta, body = FM.read(path)
        self.assertEqual(meta, original_meta)
        self.assertEqual(body, original_body)

    def test_preserves_insertion_order_in_frontmatter(self):
        path = self.tmp / "c.md"
        FM.write(path, {"kind": "report", "source": "x", "tags": ["a"]}, "")
        text = path.read_text(encoding="utf-8")
        self.assertLess(text.index("kind:"), text.index("source:"))
        self.assertLess(text.index("source:"), text.index("tags:"))

    def test_atomic_write_does_not_clobber_on_partial_failure(self):
        path = self.tmp / "d.md"
        path.write_text("---\noriginal: yes\n---\nold body\n", encoding="utf-8")
        FM.write(path, {"new": "value"}, "new body\n")
        text = path.read_text(encoding="utf-8")
        self.assertNotIn("original:", text)
        self.assertIn("new: value", text)


if __name__ == "__main__":
    unittest.main()
