import tempfile
import unittest
from pathlib import Path

from scripts.elon_orchestrator import query as Q


class FindByTagTests(unittest.TestCase):

    def setUp(self):
        self.vault = Path(tempfile.mkdtemp())
        for sub in ("records", "raw", "wiki", "reports"):
            (self.vault / sub).mkdir()

    def _file(self, rel: str, body: str) -> Path:
        path = self.vault / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
        return path

    def test_finds_tag_in_frontmatter_inline_list(self):
        a = self._file("wiki/a.md", "---\ntags: [ietf, rfc]\n---\nbody\n")
        self._file("wiki/b.md", "---\ntags: [bpf]\n---\nbody\n")
        self.assertEqual(Q.find_by_tag("ietf", self.vault), [a])

    def test_finds_tag_in_frontmatter_block_list(self):
        a = self._file("wiki/a.md", "---\ntags:\n  - ietf\n  - rfc\n---\nbody\n")
        self.assertEqual(Q.find_by_tag("rfc", self.vault), [a])

    def test_finds_tag_in_inline_hashtag(self):
        a = self._file("wiki/a.md", "# Heading\n\nThis is about #ietf and #rfc.\n")
        b = self._file("records/r.md", "no tags here\n")
        del b
        self.assertEqual(Q.find_by_tag("ietf", self.vault), [a])

    def test_returns_results_across_all_buckets(self):
        a = self._file("wiki/a.md", "---\ntags: [bpf]\n---\nx\n")
        b = self._file("records/r.md", "---\ntags: [bpf]\n---\nx\n")
        c = self._file("raw/x.md", "#bpf\n")
        results = sorted(Q.find_by_tag("bpf", self.vault))
        self.assertEqual(results, sorted([a, b, c]))

    def test_returns_empty_list_when_no_match(self):
        self._file("wiki/a.md", "---\ntags: [bpf]\n---\nx\n")
        self.assertEqual(Q.find_by_tag("nonexistent-tag", self.vault), [])

    def test_does_not_false_positive_on_substring_match(self):
        # "#ietf-old" should NOT match a search for "ietf".
        self._file("wiki/a.md", "see #ietf-old\n")
        self._file("wiki/b.md", "see #ietf\n")
        results = [p.name for p in Q.find_by_tag("ietf", self.vault)]
        self.assertEqual(results, ["b.md"])


class FindByWikilinkTargetTests(unittest.TestCase):

    def setUp(self):
        self.vault = Path(tempfile.mkdtemp())
        for sub in ("records", "raw", "wiki", "reports"):
            (self.vault / sub).mkdir()

    def _file(self, rel: str, body: str) -> Path:
        path = self.vault / rel
        path.write_text(body, encoding="utf-8")
        return path

    def test_finds_files_that_link_to_a_target(self):
        a = self._file("wiki/a.md", "see [[wiki/ietf-rfcs]]\n")
        b = self._file("wiki/b.md", "also [[wiki/ietf-rfcs|the RFCs hub]]\n")
        c = self._file("wiki/c.md", "no link here\n")
        del c
        results = sorted(Q.find_by_wikilink_target("wiki/ietf-rfcs", self.vault))
        self.assertEqual(results, sorted([a, b]))

    def test_handles_alias_pipe_in_link(self):
        a = self._file("wiki/a.md", "[[wiki/ietf-rfcs|RFCs]]\n")
        results = Q.find_by_wikilink_target("wiki/ietf-rfcs", self.vault)
        self.assertEqual(results, [a])

    def test_does_not_match_substring_of_a_longer_target(self):
        self._file("wiki/a.md", "[[wiki/ietf-rfcs-extended]]\n")
        self.assertEqual(Q.find_by_wikilink_target("wiki/ietf-rfcs", self.vault), [])

    def test_returns_empty_when_no_links(self):
        self._file("wiki/a.md", "no links\n")
        self.assertEqual(Q.find_by_wikilink_target("wiki/x", self.vault), [])


if __name__ == "__main__":
    unittest.main()
