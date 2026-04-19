import tempfile
import unittest
from pathlib import Path

from scripts.elon_orchestrator import index as IDX


_SAMPLE_INDEX = """\
# Knowledge Index

## Hubs

| Hub | Topic |
|---|---|
| [[wiki/coldstep-scope-ipv4-v1]] | Coldstep IPv4 scope |
| [[wiki/ebpf-coldstep-bpf-c]]    | BPF C runtime |
| [[wiki/ietf-rfcs]]              | IETF RFCs |

## Notes

This file is curated. Add new hubs above, alphabetical by hub slug.
"""


class AppendIndexRowTests(unittest.TestCase):

    def setUp(self):
        self.vault = Path(tempfile.mkdtemp())
        (self.vault / "wiki").mkdir()
        (self.vault / "Index.md").write_text(_SAMPLE_INDEX, encoding="utf-8")

    def _make_hub(self, slug: str, title: str) -> Path:
        path = self.vault / "wiki" / f"{slug}.md"
        path.write_text(f"# {title}\n", encoding="utf-8")
        return path

    def test_appends_new_hub_row_alphabetically(self):
        hub = self._make_hub("dns-doh", "DNS over HTTPS")
        IDX.append_index_row(hub, self.vault)
        text = (self.vault / "Index.md").read_text(encoding="utf-8")
        self.assertIn("[[wiki/dns-doh]]", text)
        # Alphabetical: dns-doh comes after coldstep-scope-ipv4-v1 and before ebpf-coldstep-bpf-c.
        coldstep_pos = text.index("coldstep-scope-ipv4-v1")
        dns_pos = text.index("dns-doh")
        ebpf_pos = text.index("ebpf-coldstep-bpf-c")
        self.assertLess(coldstep_pos, dns_pos)
        self.assertLess(dns_pos, ebpf_pos)

    def test_idempotent_when_row_already_present(self):
        hub = self._make_hub("ietf-rfcs", "IETF RFCs")
        IDX.append_index_row(hub, self.vault)
        text = (self.vault / "Index.md").read_text(encoding="utf-8")
        self.assertEqual(text.count("[[wiki/ietf-rfcs]]"), 1)

    def test_preserves_existing_table_columns_and_alignment(self):
        hub = self._make_hub("dns-doh", "DNS over HTTPS")
        IDX.append_index_row(hub, self.vault)
        text = (self.vault / "Index.md").read_text(encoding="utf-8")
        # Header rows untouched.
        self.assertIn("| Hub | Topic |", text)
        self.assertIn("|---|---|", text)
        # Notes section untouched.
        self.assertIn("This file is curated.", text)

    def test_extracts_topic_from_first_h1_of_hub(self):
        hub = self._make_hub("dns-doh", "DNS over HTTPS")
        IDX.append_index_row(hub, self.vault)
        text = (self.vault / "Index.md").read_text(encoding="utf-8")
        self.assertIn("DNS over HTTPS", text)

    def test_raises_when_hub_is_outside_wiki_bucket(self):
        rec = self.vault / "records" / "x.md"
        rec.parent.mkdir()
        rec.write_text("# X\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            IDX.append_index_row(rec, self.vault)


if __name__ == "__main__":
    unittest.main()
