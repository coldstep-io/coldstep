import unittest
from public_scripts.coldstep_detect_report.coverage_matrix_evaluator import evaluate_coverage


class TestCoverageMatrixEvaluator(unittest.TestCase):
    def test_emits_unobserved_paths(self) -> None:
        events = [{"type": "tcp"}, {"type": "http"}]
        matrix = {
            "syscalls": ["tcp", "udp", "http", "tls"],
        }
        out = evaluate_coverage(events, matrix)
        self.assertIn("udp", out["unobserved_paths"])
        self.assertIn("tls", out["unobserved_paths"])
        self.assertEqual(out["score"], 50)  # 2 of 4 observed

    def test_full_coverage(self) -> None:
        events = [{"type": "tcp"}, {"type": "udp"}, {"type": "http"}, {"type": "tls"}]
        matrix = {
            "syscalls": ["tcp", "udp", "http", "tls"],
        }
        out = evaluate_coverage(events, matrix)
        self.assertEqual(out["unobserved_paths"], [])
        self.assertEqual(out["score"], 100)

    def test_empty_matrix(self) -> None:
        events = [{"type": "tcp"}]
        matrix = {}
        out = evaluate_coverage(events, matrix)
        self.assertEqual(out["score"], 100)  # No requirements means 100%
