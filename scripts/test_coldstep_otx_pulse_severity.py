import unittest

from scripts.coldstep_otx.pulse_severity import pulse_signal_severity, severity_rank


class PulseSeverityTests(unittest.TestCase):
    def test_non_malicious_is_informational(self):
        for v in ("clean", "unidentified"):
            self.assertEqual(
                pulse_signal_severity(verdict=v, filtered_pulse_count=99),
                "Informational",
            )

    def test_malicious_tiers(self):
        self.assertEqual(pulse_signal_severity(verdict="malicious", filtered_pulse_count=0), "Low")
        self.assertEqual(pulse_signal_severity(verdict="malicious", filtered_pulse_count=4), "Low")
        self.assertEqual(pulse_signal_severity(verdict="malicious", filtered_pulse_count=5), "Medium")
        self.assertEqual(pulse_signal_severity(verdict="malicious", filtered_pulse_count=19), "Medium")
        self.assertEqual(pulse_signal_severity(verdict="malicious", filtered_pulse_count=20), "High")
        self.assertEqual(pulse_signal_severity(verdict="malicious", filtered_pulse_count=49), "High")
        self.assertEqual(pulse_signal_severity(verdict="malicious", filtered_pulse_count=50), "Critical")
        self.assertEqual(pulse_signal_severity(verdict="malicious", filtered_pulse_count=500), "Critical")

    def test_negative_count_clamped(self):
        self.assertEqual(pulse_signal_severity(verdict="malicious", filtered_pulse_count=-3), "Low")

    def test_severity_rank_sorts_critical_first(self):
        keys = ["Low", "Medium", "High", "Critical", "Informational"]
        self.assertEqual(
            sorted(keys, key=severity_rank),
            ["Critical", "High", "Medium", "Low", "Informational"],
        )


if __name__ == "__main__":
    unittest.main()
