# tests/test_baseline.py

import re
import unittest

from scanner.baseline import compute_finding_id, diff_against_baseline


def make_finding(finding="Slack", file="config.py", commit="abc123", line='token = "xoxb-secret-value"'):
    return {"finding": finding, "file": file, "commit": commit, "line": line}


def make_aws_pair(file="config.py", commit="abc123", access_key_id="AKIAABCDEF", secret_key="supersecretkey"):
    return {"file": file, "commit": commit, "access_key_id": access_key_id, "secret_key": secret_key}


class TestComputeFindingId(unittest.TestCase):
    def test_returns_16_hex_chars(self):
        finding_id = compute_finding_id(make_finding())
        self.assertTrue(re.fullmatch(r"[0-9a-f]{16}", finding_id))

    def test_stable_across_repeated_calls(self):
        finding = make_finding()
        self.assertEqual(compute_finding_id(finding), compute_finding_id(dict(finding)))

    def test_different_value_yields_different_id(self):
        a = make_finding(line='token = "value-one"')
        b = make_finding(line='token = "value-two"')
        self.assertNotEqual(compute_finding_id(a), compute_finding_id(b))

    def test_different_finding_type_yields_different_id(self):
        a = make_finding(finding="Slack")
        b = make_finding(finding="Stripe")
        self.assertNotEqual(compute_finding_id(a), compute_finding_id(b))

    def test_different_file_yields_different_id(self):
        a = make_finding(file="config.py")
        b = make_finding(file="settings.py")
        self.assertNotEqual(compute_finding_id(a), compute_finding_id(b))

    def test_different_commit_yields_different_id(self):
        a = make_finding(commit="abc123")
        b = make_finding(commit="def456")
        self.assertNotEqual(compute_finding_id(a), compute_finding_id(b))

    def test_field_boundary_does_not_collide(self):
        # Concatenating fields without a separator would make ("AB", "C") collide
        # with ("A", "BC") — assert a separator is actually used between fields.
        a = make_finding(finding="AB", file="C")
        b = make_finding(finding="A", file="BC")
        self.assertNotEqual(compute_finding_id(a), compute_finding_id(b))

    def test_aws_pair_uses_access_and_secret_key(self):
        a = make_aws_pair(access_key_id="AKIAONE", secret_key="secretone")
        b = make_aws_pair(access_key_id="AKIAONE", secret_key="secrettwo")
        self.assertNotEqual(compute_finding_id(a), compute_finding_id(b))

    def test_aws_pair_and_regular_finding_do_not_collide(self):
        # Same file/commit, but one is an AWS pair and the other a regular
        # finding with no matching "access_key_id" key — must not collide
        # just because file/commit happen to match.
        pair = make_aws_pair(file="shared.py", commit="abc123")
        finding = make_finding(file="shared.py", commit="abc123")
        self.assertNotEqual(compute_finding_id(pair), compute_finding_id(finding))

    def test_aws_pair_stable_across_repeated_calls(self):
        pair = make_aws_pair()
        self.assertEqual(compute_finding_id(pair), compute_finding_id(dict(pair)))


class TestDiffAgainstBaseline(unittest.TestCase):
    def test_empty_previous_ids_means_everything_is_new(self):
        findings = [make_finding(line='a = "one"'), make_finding(line='a = "two"')]
        pairs = [make_aws_pair()]

        new_findings, previously_seen, current_ids = diff_against_baseline(findings, pairs, set())

        self.assertEqual(len(new_findings), 3)
        self.assertEqual(previously_seen, [])
        self.assertEqual(len(current_ids), 3)

    def test_previously_seen_ids_are_suppressed_from_new(self):
        findings = [make_finding(line='a = "one"'), make_finding(line='a = "two"')]
        previous_ids = {compute_finding_id(findings[0])}

        new_findings, previously_seen, current_ids = diff_against_baseline(findings, [], previous_ids)

        self.assertEqual(new_findings, [findings[1]])
        self.assertEqual(previously_seen, [findings[0]])
        self.assertEqual(current_ids, {compute_finding_id(findings[0]), compute_finding_id(findings[1])})

    def test_current_ids_matches_full_input_set_regardless_of_baseline(self):
        findings = [make_finding(line='a = "one"')]
        pairs = [make_aws_pair()]
        previous_ids = {"not-a-real-id-in-this-scan"}

        _, _, current_ids = diff_against_baseline(findings, pairs, previous_ids)

        expected = {compute_finding_id(findings[0]), compute_finding_id(pairs[0])}
        self.assertEqual(current_ids, expected)

    def test_all_previously_seen_yields_no_new_findings(self):
        findings = [make_finding(line='a = "one"'), make_finding(line='a = "two"')]
        previous_ids = {compute_finding_id(f) for f in findings}

        new_findings, previously_seen, current_ids = diff_against_baseline(findings, [], previous_ids)

        self.assertEqual(new_findings, [])
        self.assertEqual(previously_seen, findings)


if __name__ == "__main__":
    unittest.main()
