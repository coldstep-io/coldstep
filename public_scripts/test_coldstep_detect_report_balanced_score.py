import unittest
from public_scripts.coldstep_detect_report.balanced_score import compute_balanced_score


class TestBalancedScore(unittest.TestCase):
    def test_weighted_score_and_verdict(self) -> None:
        # Example: high integrity, medium coverage
        out = compute_balanced_score(
            integrity_score=100,
            coverage_score=70,
            correlation_score=100,
            weights={"integrity": 0.5, "coverage": 0.4, "correlation": 0.1},
            fail_threshold=60,
            pass_threshold=80,
            hard_fail_reasons=[],
        )
        # 100*0.5 + 70*0.4 + 100*0.1 = 50 + 28 + 10 = 88
        self.assertEqual(out["score"], 88)
        self.assertEqual(out["verdict"], "pass")

    def test_warn_verdict(self) -> None:
        out = compute_balanced_score(
            integrity_score=100,
            coverage_score=40,
            correlation_score=100,
            weights={"integrity": 0.5, "coverage": 0.4, "correlation": 0.1},
            fail_threshold=60,
            pass_threshold=80,
            hard_fail_reasons=[],
        )
        # 100*0.5 + 40*0.4 + 100*0.1 = 50 + 16 + 10 = 76
        self.assertEqual(out["score"], 76)
        self.assertEqual(out["verdict"], "warn")

    def test_fail_verdict(self) -> None:
        out = compute_balanced_score(
            integrity_score=50,
            coverage_score=20,
            correlation_score=50,
            weights={"integrity": 0.5, "coverage": 0.4, "correlation": 0.1},
            fail_threshold=60,
            pass_threshold=80,
            hard_fail_reasons=[],
        )
        # 50*0.5 + 20*0.4 + 50*0.1 = 25 + 8 + 5 = 38
        self.assertEqual(out["score"], 38)
        self.assertEqual(out["verdict"], "fail")

    def test_hard_fail(self) -> None:
        out = compute_balanced_score(
            integrity_score=100,
            coverage_score=100,
            correlation_score=100,
            weights={"integrity": 0.5, "coverage": 0.4, "correlation": 0.1},
            fail_threshold=60,
            pass_threshold=80,
            hard_fail_reasons=["INTEGRITY_CANARY_MISSING"],
        )
        self.assertEqual(out["score"], 0)
        self.assertEqual(out["verdict"], "fail")
        self.assertIn("INTEGRITY_CANARY_MISSING", out["reasons"])
