import json

from scanner.remediation import (
    REMEDIATION_TEMPLATES,
    get_remediation_advice,
    route_remediation,
    generate_report,
)


def test_critical_and_high_severity_trigger_alert_and_advise():
    critical = route_remediation({"finding": "AWS API Key", "severity": "Critical"})
    high = route_remediation({"finding": "github_token", "severity": "High"})

    assert critical["action_taken"] == "alert_and_advise"
    assert high["action_taken"] == "alert_and_advise"
    assert "remediation" in critical
    assert "remediation" in high


def test_medium_severity_logged_for_digest():
    result = route_remediation({"finding": "Slack", "severity": "Medium"})

    assert result["action_taken"] == "logged_for_digest"
    assert "remediation" not in result


def test_low_severity_logged_only():
    result = route_remediation({"finding": "Slack", "severity": "Low"})

    assert result["action_taken"] == "logged_only"
    assert "remediation" not in result


def test_get_remediation_advice_maps_known_types():
    aws_advice = get_remediation_advice("AWS API Key")
    github_advice = get_remediation_advice("github_token")
    unknown_advice = get_remediation_advice("Some Unrecognized Pattern")

    assert aws_advice["category"] == "aws"
    assert aws_advice["docs_url"] == REMEDIATION_TEMPLATES["aws"]["docs_url"]

    assert github_advice["category"] == "github"
    assert github_advice["docs_url"] == REMEDIATION_TEMPLATES["github"]["docs_url"]

    assert unknown_advice["category"] == "generic"
    assert unknown_advice["docs_url"] == REMEDIATION_TEMPLATES["generic"]["docs_url"]


def test_generate_report_produces_valid_json_with_expected_keys(tmp_path):
    findings = [{"finding": "github_token", "severity": "High", "score": 70, "file": "src/app.py"}]
    aws_pairs = [{"finding": "AWS pair", "severity": "Critical", "score": 90, "file": "src/config.py"}]

    filepath = tmp_path / "findings.json"
    generate_report(findings, aws_pairs, filepath=str(filepath))

    with open(filepath, "r", encoding="utf-8") as f:
        report = json.load(f)

    assert "generated_at" in report
    assert report["total_findings"] == 2
    assert report["findings"] == findings
    assert report["aws_pairs"] == aws_pairs
