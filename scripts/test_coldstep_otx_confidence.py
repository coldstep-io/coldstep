from __future__ import annotations

import unittest

from scripts.coldstep_otx.confidence import (
    PULSE_HARD_DROP_RE,
    GENERIC_LIST_NAME_RE,
    _filtered_pulses,
    tier,
)


def _pulse(**kw):
    base = {
        "id": "p",
        "name": "Emotet campaign",
        "modified": "2026-04-01T00:00:00Z",
        "is_subscribing": True,
        "malware_families": [{"display_name": "Emotet"}],
        "attack_ids": [],
    }
    base.update(kw)
    return base


def _general(pulses):
    return {"pulse_info": {"count": len(pulses), "pulses": pulses}}


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


class TierOtxOnlyTests(unittest.TestCase):
    def test_start_at_high_when_nothing_demotes(self):
        g = _general([_pulse(id="a"), _pulse(id="b")])
        t, reasons = tier(g)
        self.assertEqual(t, "high")
        self.assertEqual(reasons, [])

    def test_single_pulse_demotes_high_to_medium(self):
        g = _general([_pulse(id="a")])
        t, reasons = tier(g)
        self.assertEqual(t, "medium")
        self.assertIn("single pulse hit (count=1)", reasons)

    def test_no_malware_family_and_no_attack_ids_demotes(self):
        g = _general([
            _pulse(id="a", malware_families=[], attack_ids=[]),
            _pulse(id="b", malware_families=[], attack_ids=[]),
        ])
        t, reasons = tier(g)
        self.assertEqual(t, "medium")
        self.assertIn("no malware_families or attack_ids on any pulse", reasons)

    def test_attack_ids_alone_keeps_high(self):
        g = _general([
            _pulse(id="a", malware_families=[], attack_ids=[{"id": "T1071.001"}]),
            _pulse(id="b", malware_families=[], attack_ids=[{"id": "T1566"}]),
        ])
        t, _ = tier(g)
        self.assertEqual(t, "high")

    def test_stale_pulse_demotes(self):
        g = _general([
            _pulse(id="a", modified="2024-01-01T00:00:00Z"),
            _pulse(id="b", modified="2024-02-01T00:00:00Z"),
        ])
        t, reasons = tier(g)
        self.assertEqual(t, "medium")
        self.assertTrue(any("stale" in r for r in reasons))

    def test_all_generic_list_collapses_to_low(self):
        g = _general([
            _pulse(id="a", name="T-Pot Mass IP IoC Export"),
            _pulse(id="b", name="AbuseIPDB dump 2026-04"),
        ])
        t, reasons = tier(g)
        self.assertEqual(t, "low")
        self.assertTrue(any("generic-list" in r for r in reasons))

    def test_mixed_generic_and_curated_stays_above_low(self):
        # One curated pulse means we do NOT collapse to low.
        g = _general([
            _pulse(id="a", name="T-Pot Mass IP IoC Export"),
            _pulse(id="b", name="Lazarus Q2 IOCs"),
        ])
        t, _ = tier(g)
        self.assertIn(t, ("high", "medium"))

    def test_stacking_demotions_with_floor(self):
        # single pulse (high→medium) + no mal fam (medium→low) + stale (low→low)
        g = _general([_pulse(id="a", malware_families=[], attack_ids=[],
                             modified="2023-01-01T00:00:00Z")])
        t, reasons = tier(g)
        self.assertEqual(t, "low")
        self.assertEqual(len(reasons), 3)

    def test_none_general_returns_medium_with_zero_pulse_reason(self):
        # Defensive: None general yields empty pulse list → count=0
        # → "single pulse hit (count=0)" demote (0 < 2).
        t, reasons = tier(None)
        self.assertEqual(t, "medium")
        self.assertIn("single pulse hit (count=0)", reasons)


if __name__ == "__main__":
    unittest.main()
