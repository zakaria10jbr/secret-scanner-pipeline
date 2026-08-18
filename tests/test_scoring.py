# tests/test_scoring.py

import unittest

from scanner.scoring import (
    score_finding,
    score_to_severity,
    DEFAULT_TYPE_WEIGHT,
    VERIFICATION_WEIGHTS,
)


class TestScoreFinding(unittest.TestCase):
    def test_live_aws_key_is_critical_or_high(self):
        result = score_finding("AWS API Key", "live")
        self.assertIn(result["severity"], ("Critical", "High"))
        self.assertGreaterEqual(result["score"], 45)

    def test_dead_aws_key_is_low_override(self):
        result = score_finding("AWS API Key", "dead")
        self.assertEqual(result["severity"], "Low")

    def test_unverifiable_scores_higher_than_dead(self):
        unverifiable_result = score_finding("AWS API Key", "unverifiable")
        dead_result = score_finding("AWS API Key", "dead")
        self.assertGreater(unverifiable_result["score"], dead_result["score"])

    def test_unrecognized_finding_type_falls_back_to_default_weight(self):
        result = score_finding("Totally Unknown Secret Type XYZ", "unverifiable")
        expected_score = DEFAULT_TYPE_WEIGHT + VERIFICATION_WEIGHTS["unverifiable"]
        self.assertEqual(result["score"], expected_score)

    def test_file_path_test_marker_scores_exactly_30_lower(self):
        # "Slack" (weight 20) + "unverifiable" (weight 15) = 35, well above the
        # 30-point penalty floor, so the subtraction won't clip at 0 here.
        baseline_none = score_finding("Slack", "unverifiable", file_path=None)
        baseline_src = score_finding("Slack", "unverifiable", file_path="src/config.py")
        penalized = score_finding("Slack", "unverifiable", file_path="tests/test_config.py")

        self.assertEqual(baseline_none["score"], baseline_src["score"])
        self.assertEqual(baseline_none["score"] - penalized["score"], 30)

    def test_file_path_penalty_floors_at_zero(self):
        # Unrecognized type (weight 15) + "dead" (weight 0) = 15, so a flat -30
        # penalty would go negative and must be floored at 0 instead.
        baseline = score_finding("Totally Unknown Secret Type XYZ", "dead", file_path=None)
        penalized = score_finding(
            "Totally Unknown Secret Type XYZ", "dead", file_path="tests/test_config.py"
        )
        self.assertLess(baseline["score"], 30)
        self.assertEqual(penalized["score"], 0)


class TestScoreToSeverity(unittest.TestCase):
    def test_critical_boundary(self):
        self.assertEqual(score_to_severity(70), "Critical")
        self.assertEqual(score_to_severity(69), "High")

    def test_high_boundary(self):
        self.assertEqual(score_to_severity(45), "High")
        self.assertEqual(score_to_severity(44), "Medium")

    def test_medium_boundary(self):
        self.assertEqual(score_to_severity(25), "Medium")
        self.assertEqual(score_to_severity(24), "Low")

    def test_low_floor(self):
        self.assertEqual(score_to_severity(0), "Low")


if __name__ == "__main__":
    unittest.main()
