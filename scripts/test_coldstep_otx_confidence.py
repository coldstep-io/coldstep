from __future__ import annotations

import unittest

from scripts.coldstep_otx.confidence import (
    PULSE_HARD_DROP_RE,
    GENERIC_LIST_NAME_RE,
    KNOWN_CLOUD_ASNS,
    CLOUD_DNS_RE,
    _demote,
)


class RegexTests(unittest.TestCase):
    def test_hard_drop_matches_troll(self):
        for name in ["dont subscribe", "Dont-Subscribe", "test pulse", "wallpaper"]:
            self.assertIsNotNone(PULSE_HARD_DROP_RE.search(name), name)

    def test_hard_drop_does_not_match_real(self):
        for name in ["Emotet Q2 IOCs", "APT38 infra", "T-Pot Mass IP IoC Export"]:
            self.assertIsNone(PULSE_HARD_DROP_RE.search(name), name)

    def test_generic_list_matches_feeds(self):
        for name in [
            "T-Pot Mass IP IoC Export",
            "TPot honeypot feed",
            "Malicious IP list",
            "AbuseIPDB dump",
            "port scanners",
            "IOC Sweep 2025-Q4",
        ]:
            self.assertIsNotNone(GENERIC_LIST_NAME_RE.search(name), name)

    def test_generic_list_does_not_match_curated(self):
        for name in ["Lazarus Q2 IOCs", "APT38 infra", "Emotet C2"]:
            self.assertIsNone(GENERIC_LIST_NAME_RE.search(name), name)


if __name__ == "__main__":
    unittest.main()
