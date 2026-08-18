# tests/test_main.py

import unittest

from main import severities_at_or_above, SEVERITY_ORDER


class TestSeveritiesAtOrAbove(unittest.TestCase):
    def test_high_includes_critical_and_high_only(self):
        self.assertEqual(severities_at_or_above("high"), ["Critical", "High"])

    def test_critical_includes_critical_only(self):
        self.assertEqual(severities_at_or_above("critical"), ["Critical"])

    def test_low_includes_everything(self):
        self.assertEqual(severities_at_or_above("low"), list(SEVERITY_ORDER))

    def test_medium_includes_critical_high_medium(self):
        self.assertEqual(severities_at_or_above("medium"), ["Critical", "High", "Medium"])

    def test_is_case_insensitive(self):
        self.assertEqual(severities_at_or_above("HIGH"), ["Critical", "High"])
        self.assertEqual(severities_at_or_above("High"), ["Critical", "High"])

    def test_none_threshold_includes_everything(self):
        self.assertEqual(severities_at_or_above(None), list(SEVERITY_ORDER))

    def test_unrecognized_threshold_includes_everything(self):
        self.assertEqual(severities_at_or_above("not-a-real-level"), list(SEVERITY_ORDER))


if __name__ == "__main__":
    unittest.main()
