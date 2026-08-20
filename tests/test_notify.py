# tests/test_notify.py

import unittest
from unittest import mock

from scanner.notify import create_github_issue, _build_issue_body, _match_github_slug


def make_finding(**overrides):
    finding = {
        "finding": "Github Personal Access Token",
        "file": "config/secrets.py",
        "commit": "abc12345",
        "line": 'token = "ghp_realSecretValueThatMustNeverLeak12345"',
        "verification_status": "live",
        "score": 70,
        "severity": "Critical",
        "remediation": {
            "category": "github",
            "immediate_actions": [
                "1. Revoke the exposed token immediately.",
                "2. Check the token's recent activity.",
            ],
            "rotation_guidance": "Generate a new token, update consumers, revoke the old one.",
            "docs_url": "https://docs.github.com/example",
        },
    }
    finding.update(overrides)
    return finding


def make_aws_pair(**overrides):
    pair = {
        "finding": "AWS pair",
        "file": "infra/main.tf",
        "commit": "def67890",
        "access_key_id": "AKIAREALVALUEDONOTLEAK",
        "secret_key": "supersecretrealvaluedonotleak",
        "status": "dead",
        "score": 40,
        "severity": "High",
        "remediation": {
            "category": "aws",
            "immediate_actions": ["1. Deactivate the exposed IAM access key immediately."],
            "rotation_guidance": "Create a new access key pair.",
            "docs_url": "https://docs.aws.amazon.com/example",
        },
    }
    pair.update(overrides)
    return pair


class TestBuildIssueBody(unittest.TestCase):
    def test_never_includes_the_secret_value(self):
        finding = make_finding()
        body = _build_issue_body(finding)
        self.assertNotIn("ghp_realSecretValueThatMustNeverLeak12345", body)
        self.assertNotIn(finding["line"], body)

    def test_never_includes_aws_pair_credential_values(self):
        pair = make_aws_pair()
        body = _build_issue_body(pair)
        self.assertNotIn("AKIAREALVALUEDONOTLEAK", body)
        self.assertNotIn("supersecretrealvaluedonotleak", body)

    def test_includes_metadata_fields(self):
        finding = make_finding()
        body = _build_issue_body(finding)
        self.assertIn("config/secrets.py", body)
        self.assertIn("abc12345", body)
        self.assertIn("LIVE", body)
        self.assertIn("70", body)

    def test_includes_remediation_advice(self):
        finding = make_finding()
        body = _build_issue_body(finding)
        self.assertIn("Revoke the exposed token immediately", body)
        self.assertIn("Generate a new token, update consumers, revoke the old one.", body)
        self.assertIn("https://docs.github.com/example", body)

    def test_aws_pair_status_field_used_when_verification_status_absent(self):
        pair = make_aws_pair(status="dead")
        body = _build_issue_body(pair)
        self.assertIn("DEAD", body)

    def test_missing_remediation_does_not_crash(self):
        finding = make_finding(remediation=None)
        body = _build_issue_body(finding)
        self.assertIn("config/secrets.py", body)


class TestMatchGithubSlug(unittest.TestCase):
    def test_https_url(self):
        self.assertEqual(_match_github_slug("https://github.com/example/some-repo.git"), "example/some-repo")

    def test_ssh_url(self):
        self.assertEqual(_match_github_slug("git@github.com:example/some-repo.git"), "example/some-repo")

    def test_https_url_without_git_suffix(self):
        self.assertEqual(_match_github_slug("https://github.com/example/some-repo"), "example/some-repo")

    def test_non_github_url_returns_none(self):
        self.assertIsNone(_match_github_slug("https://gitlab.com/example/some-repo.git"))

    def test_none_input_returns_none(self):
        self.assertIsNone(_match_github_slug(None))

    def test_empty_string_returns_none(self):
        self.assertIsNone(_match_github_slug(""))


class TestCreateGithubIssue(unittest.TestCase):
    def test_returns_issue_url_on_success(self):
        finding = make_finding()
        mock_response = mock.Mock(status_code=201)
        mock_response.json.return_value = {"html_url": "https://github.com/example/some-repo/issues/1"}

        with mock.patch("scanner.notify.requests.post", return_value=mock_response) as mock_post:
            result = create_github_issue(finding, "example", "some-repo", "fake-token-123")

        self.assertEqual(result, "https://github.com/example/some-repo/issues/1")
        mock_post.assert_called_once()

    def test_sends_correct_title_and_auth_header(self):
        finding = make_finding(severity="Critical", finding="Github Personal Access Token", file="config/secrets.py")
        mock_response = mock.Mock(status_code=201)
        mock_response.json.return_value = {"html_url": "https://github.com/example/some-repo/issues/1"}

        with mock.patch("scanner.notify.requests.post", return_value=mock_response) as mock_post:
            create_github_issue(finding, "example", "some-repo", "fake-token-123")

        call_kwargs = mock_post.call_args.kwargs
        self.assertEqual(
            call_kwargs["json"]["title"],
            "[secretscan] Critical secret detected: Github Personal Access Token in config/secrets.py",
        )
        self.assertEqual(call_kwargs["headers"]["Authorization"], "token fake-token-123")
        self.assertEqual(
            mock_post.call_args.args[0],
            "https://api.github.com/repos/example/some-repo/issues",
        )

    def test_issue_body_never_contains_the_secret_value(self):
        finding = make_finding()
        mock_response = mock.Mock(status_code=201)
        mock_response.json.return_value = {"html_url": "https://github.com/example/some-repo/issues/1"}

        with mock.patch("scanner.notify.requests.post", return_value=mock_response) as mock_post:
            create_github_issue(finding, "example", "some-repo", "fake-token-123")

        body = mock_post.call_args.kwargs["json"]["body"]
        self.assertNotIn("ghp_realSecretValueThatMustNeverLeak12345", body)

    def test_returns_none_on_auth_failure(self):
        finding = make_finding()
        mock_response = mock.Mock(status_code=401)

        with mock.patch("scanner.notify.requests.post", return_value=mock_response):
            result = create_github_issue(finding, "example", "some-repo", "invalid-token")

        self.assertIsNone(result)

    def test_returns_none_on_network_error_and_does_not_raise(self):
        finding = make_finding()

        with mock.patch("scanner.notify.requests.post", side_effect=ConnectionError("network unreachable")):
            result = create_github_issue(finding, "example", "some-repo", "fake-token-123")

        self.assertIsNone(result)

    def test_returns_none_on_rate_limit(self):
        finding = make_finding()
        mock_response = mock.Mock(status_code=403)

        with mock.patch("scanner.notify.requests.post", return_value=mock_response):
            result = create_github_issue(finding, "example", "some-repo", "fake-token-123")

        self.assertIsNone(result)

    def test_returns_none_on_malformed_success_response(self):
        finding = make_finding()
        mock_response = mock.Mock(status_code=201)
        mock_response.json.side_effect = ValueError("not JSON")

        with mock.patch("scanner.notify.requests.post", return_value=mock_response):
            result = create_github_issue(finding, "example", "some-repo", "fake-token-123")

        self.assertIsNone(result)

    def test_works_for_aws_pair_findings_too(self):
        pair = make_aws_pair()
        mock_response = mock.Mock(status_code=201)
        mock_response.json.return_value = {"html_url": "https://github.com/example/some-repo/issues/2"}

        with mock.patch("scanner.notify.requests.post", return_value=mock_response):
            result = create_github_issue(pair, "example", "some-repo", "fake-token-123")

        self.assertEqual(result, "https://github.com/example/some-repo/issues/2")


if __name__ == "__main__":
    unittest.main()
