# tests/test_remediation.py

import json
import os
import tempfile
import unittest

from scanner.remediation import (
    route_remediation,
    get_remediation_advice,
    generate_report,
    cleanup_old_reports,
)


class TestRouteRemediation(unittest.TestCase):
    def test_critical_severity_alerts_and_advises(self):
        result = route_remediation({"severity": "Critical", "finding": "AWS API Key"})
        self.assertEqual(result["action_taken"], "alert_and_advise")

    def test_high_severity_alerts_and_advises(self):
        result = route_remediation({"severity": "High", "finding": "Github Personal Access Token"})
        self.assertEqual(result["action_taken"], "alert_and_advise")

    def test_medium_severity_logged_for_digest(self):
        result = route_remediation({"severity": "Medium", "finding": "Some Generic Secret"})
        self.assertEqual(result["action_taken"], "logged_for_digest")

    def test_low_severity_logged_only(self):
        result = route_remediation({"severity": "Low", "finding": "Some Generic Secret"})
        self.assertEqual(result["action_taken"], "logged_only")


class TestGetRemediationAdvice(unittest.TestCase):
    def test_aws_type_maps_to_aws_template(self):
        self.assertEqual(get_remediation_advice("AWS API Key")["category"], "aws")

    def test_github_type_maps_to_github_template(self):
        self.assertEqual(get_remediation_advice("Github Personal Access Token")["category"], "github")

    def test_stripe_type_maps_to_stripe_template(self):
        self.assertEqual(get_remediation_advice("Stripe API Key - 1")["category"], "stripe")

    def test_slack_type_maps_to_slack_template(self):
        self.assertEqual(get_remediation_advice("Slack")["category"], "slack")

    def test_unrecognized_type_maps_to_generic_template(self):
        self.assertEqual(get_remediation_advice("Some Totally Unknown Type")["category"], "generic")


class TestGenerateReport(unittest.TestCase):
    def test_report_has_expected_top_level_keys(self):
        findings = [{"finding": "Slack", "severity": "Low"}]
        aws_pairs = [{"access_key_id": "AKIA...", "status": "dead"}]

        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, "test_report.json")
            returned_path = generate_report(findings, aws_pairs, filepath=filepath)

            self.assertEqual(returned_path, filepath)
            with open(filepath, "r", encoding="utf-8") as f:
                report = json.load(f)

            expected_keys = {"generated_at", "total_findings", "findings", "aws_pairs"}
            self.assertEqual(set(report.keys()), expected_keys)
            self.assertEqual(report["total_findings"], len(findings) + len(aws_pairs))
            self.assertEqual(report["findings"], findings)
            self.assertEqual(report["aws_pairs"], aws_pairs)

    def test_default_filepath_is_timestamped_under_reports_dir(self):
        path = generate_report([], [])
        try:
            self.assertTrue(path.startswith("reports/findings_"))
            self.assertTrue(path.endswith(".json"))
            # Filesystem-safe on Windows: no colons or other reserved characters.
            self.assertNotIn(":", os.path.basename(path))
            self.assertTrue(os.path.exists(path))
        finally:
            if os.path.exists(path):
                os.remove(path)


class TestCleanupOldReports(unittest.TestCase):
    def test_keeps_only_the_most_recent_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            filenames = [f"findings_2026-01-{day:02d}_120000.json" for day in range(1, 16)]  # 15 files
            for name in filenames:
                with open(os.path.join(tmpdir, name), "w", encoding="utf-8") as f:
                    f.write("{}")

            cleanup_old_reports(reports_dir=tmpdir, keep=10)

            remaining = sorted(os.listdir(tmpdir))
            self.assertEqual(len(remaining), 10)
            self.assertEqual(remaining, sorted(filenames)[-10:])

    def test_noop_when_fewer_files_than_the_limit(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "findings_2026-01-01_120000.json"), "w", encoding="utf-8") as f:
                f.write("{}")

            cleanup_old_reports(reports_dir=tmpdir, keep=10)  # must not raise

            self.assertEqual(os.listdir(tmpdir), ["findings_2026-01-01_120000.json"])

    def test_ignores_files_not_matching_the_report_naming_pattern(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "findings.json"), "w", encoding="utf-8") as f:
                f.write("{}")  # old fixed-name file, predates timestamped reports
            with open(os.path.join(tmpdir, "notes.txt"), "w", encoding="utf-8") as f:
                f.write("unrelated")

            cleanup_old_reports(reports_dir=tmpdir, keep=0)

            remaining = sorted(os.listdir(tmpdir))
            self.assertEqual(remaining, ["findings.json", "notes.txt"])


if __name__ == "__main__":
    unittest.main()
