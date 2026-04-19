from __future__ import annotations

import unittest

from scripts.coldstep_otx.confidence import (
    PULSE_HARD_DROP_RE,
    GENERIC_LIST_NAME_RE,
    KNOWN_CLOUD_ASNS,
    CLOUD_DNS_RE,
    _demote,
    _filtered_pulses,
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


class FilteredPulsesTests(unittest.TestCase):
    def _make(self, pulses):
        return {"pulse_info": {"pulses": pulses}}

    def test_hard_drop_removes_troll_pulses(self):
        g = self._make([
            {"id": "1", "name": "dont subscribe"},
            {"id": "2", "name": "Emotet Q2 IOCs"},
        ])
        kept = _filtered_pulses(g)
        self.assertEqual([p["id"] for p in kept], ["2"])

    def test_is_subscribing_filter_when_any_present_and_mixed(self):
        g = self._make([
            {"id": "1", "name": "A", "is_subscribing": True},
            {"id": "2", "name": "B", "is_subscribing": False},
            {"id": "3", "name": "C", "is_subscribing": True},
        ])
        kept = _filtered_pulses(g)
        self.assertEqual(sorted(p["id"] for p in kept), ["1", "3"])

    def test_is_subscribing_graceful_degrade_when_all_false(self):
        # Graylog #84 bug: API returns is_subscribing=False on every pulse
        # even for subscribed accounts. When ALL surviving pulses report
        # False, skip the filter to avoid dropping everything.
        g = self._make([
            {"id": "1", "name": "A", "is_subscribing": False},
            {"id": "2", "name": "B", "is_subscribing": False},
        ])
        kept = _filtered_pulses(g)
        self.assertEqual(sorted(p["id"] for p in kept), ["1", "2"])

    def test_no_is_subscribing_field_skips_filter(self):
        g = self._make([
            {"id": "1", "name": "A"},
            {"id": "2", "name": "B"},
        ])
        kept = _filtered_pulses(g)
        self.assertEqual(sorted(p["id"] for p in kept), ["1", "2"])

    def test_hard_drop_happens_even_when_is_subscribing_true(self):
        g = self._make([
            {"id": "1", "name": "dont subscribe", "is_subscribing": True},
            {"id": "2", "name": "real", "is_subscribing": True},
        ])
        kept = _filtered_pulses(g)
        self.assertEqual([p["id"] for p in kept], ["2"])

    def test_empty_pulses_returns_empty(self):
        self.assertEqual(_filtered_pulses({}), [])
        self.assertEqual(_filtered_pulses(None), [])
        self.assertEqual(_filtered_pulses({"pulse_info": {}}), [])


if __name__ == "__main__":
    unittest.main()
