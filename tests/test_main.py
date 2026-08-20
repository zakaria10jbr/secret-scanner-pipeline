# tests/test_main.py

import unittest

from main import severities_at_or_above, count_findings_at_or_above, SEVERITY_ORDER


def make_finding(severity):
    return {"severity": severity}


def make_aws_pair(severity):
    return {"severity": severity}


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


class TestCountFindingsAtOrAbove(unittest.TestCase):
    def test_counts_only_findings_at_or_above_threshold(self):
        results = [make_finding("Critical"), make_finding("High"), make_finding("Medium"), make_finding("Low")]
        self.assertEqual(count_findings_at_or_above(results, [], "high"), 2)

    def test_critical_threshold_only_counts_critical(self):
        results = [make_finding("Critical"), make_finding("Critical"), make_finding("High")]
        self.assertEqual(count_findings_at_or_above(results, [], "critical"), 2)

    def test_low_threshold_counts_everything(self):
        results = [make_finding("Critical"), make_finding("High"), make_finding("Medium"), make_finding("Low")]
        self.assertEqual(count_findings_at_or_above(results, [], "low"), 4)

    def test_zero_when_nothing_qualifies(self):
        results = [make_finding("Medium"), make_finding("Low")]
        self.assertEqual(count_findings_at_or_above(results, [], "critical"), 0)

    def test_aws_pairs_counted_alongside_regular_findings(self):
        results = [make_finding("High")]
        pairs = [make_aws_pair("Critical"), make_aws_pair("Low")]
        self.assertEqual(count_findings_at_or_above(results, pairs, "high"), 2)

    def test_empty_inputs_yield_zero(self):
        self.assertEqual(count_findings_at_or_above([], [], "low"), 0)


if __name__ == "__main__":
    unittest.main()
