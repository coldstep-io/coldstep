import tempfile
import unittest
from pathlib import Path

from scripts.elon_orchestrator import persona as P


_SAMPLE_PERSONA = """\
orchestrator:
  fp: 0.25
  vi: 0.25
  sh: 0.50
  co: 0.00
code-reviewer:
  fp: 0.40
  vi: 0.30
  sh: 0.30
  co: 0.00
ask-elon:
  fp: 0.30
  vi: 0.30
  sh: 0.10
  co: 0.30
"""


class LoadPersonaDialTests(unittest.TestCase):

    def setUp(self):
        self.vault = Path(tempfile.mkdtemp())
        (self.vault / ".elon").mkdir()
        (self.vault / ".elon" / "persona.yml").write_text(_SAMPLE_PERSONA, encoding="utf-8")

    def test_loads_dial_for_named_skill(self):
        dial = P.load_persona_dial("orchestrator", self.vault)
        self.assertEqual(dial, {"fp": 0.25, "vi": 0.25, "sh": 0.50, "co": 0.00})

    def test_loads_dial_for_a_different_skill(self):
        dial = P.load_persona_dial("ask-elon", self.vault)
        self.assertAlmostEqual(dial["co"], 0.30)
        self.assertAlmostEqual(sum(dial.values()), 1.00, places=2)

    def test_returns_neutral_dial_for_unknown_skill(self):
        dial = P.load_persona_dial("totally-unknown", self.vault)
        self.assertEqual(dial, {"fp": 0.25, "vi": 0.25, "sh": 0.25, "co": 0.25})

    def test_returns_neutral_dial_when_file_missing(self):
        empty_vault = Path(tempfile.mkdtemp())
        dial = P.load_persona_dial("orchestrator", empty_vault)
        self.assertEqual(dial, {"fp": 0.25, "vi": 0.25, "sh": 0.25, "co": 0.25})


if __name__ == "__main__":
    unittest.main()
