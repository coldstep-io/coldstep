import unittest
from public_scripts.coldstep_detect_report.integrity_evaluator import evaluate_integrity


class TestIntegrityEvaluator(unittest.TestCase):
    def test_fails_when_required_type_missing(self) -> None:
        events = [{"type": "meta"}, {"type": "exec"}]
        # We expect 'tcp' to be required but it's missing
        result = evaluate_integrity(events, require_types={"meta", "exec", "tcp"}, canary_rules=[])
        self.assertEqual(result["status"], "fail")
        self.assertIn("INTEGRITY_REQUIRED_TYPE_MISSING", result["reasons"])

    def test_fails_when_canary_missing(self) -> None:
        events = [{"type": "meta"}, {"type": "exec"}, {"type": "tcp"}]
        # Canary requires a 'udp' event which is missing
        canary = [{"id": "canary_udp", "predicate": {"type": "udp"}}]
        result = evaluate_integrity(events, require_types={"meta", "exec", "tcp"}, canary_rules=canary)
        self.assertEqual(result["status"], "fail")
        self.assertIn("INTEGRITY_CANARY_MISSING", result["reasons"])

    def test_passes_when_all_present(self) -> None:
        events = [
            {"type": "meta"},
            {"type": "exec", "comm": "ls"},
            {"type": "tcp"},
            {"type": "udp"}
        ]
        canary = [{"id": "canary_ls", "predicate": {"type": "exec", "comm": "ls"}}]
        result = evaluate_integrity(events, require_types={"meta", "exec", "tcp"}, canary_rules=canary)
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["score"], 100)
        self.assertEqual(result["reasons"], [])
