# tests/test_verifier.py

import random
import unittest
from unittest import mock

from scanner.verifier import pair_and_verify_aws, _candidate_sort_key


def make_access_key(commit="abc123", file="config.py", value="AKIAABCDEFGHIJKLMNOP"):
    return {
        "finding": "AWS API Key",
        "commit": commit,
        "file": file,
        "line": f'aws_access_key_id = "{value}"',
        "still_present": True,
    }


def make_candidate(commit="abc123", file="config.py", value="candidate-secret",
                    finding="High entropy string (entropy=4.50)"):
    return {
        "finding": finding,
        "commit": commit,
        "file": file,
        "line": f'aws_secret_access_key = "{value}"',
    }


class TestCandidateSortKey(unittest.TestCase):
    def test_sorts_by_extracted_value_primarily(self):
        lower = make_candidate(value="apple")
        higher = make_candidate(value="banana")
        self.assertLess(_candidate_sort_key(lower), _candidate_sort_key(higher))

    def test_ties_on_value_broken_by_finding_type(self):
        a_type = make_candidate(value="same-value", finding="A type")
        z_type = make_candidate(value="same-value", finding="Z type")
        self.assertLess(_candidate_sort_key(a_type), _candidate_sort_key(z_type))


class TestAwsCandidateSelectionIsDeterministic(unittest.TestCase):
    def test_same_candidate_selected_across_shuffled_orders_and_repeated_calls(self):
        # Previously: when every candidate verified "dead", the code kept
        # overwriting its pick on each subsequent "dead" result, so the
        # *last* one it happened to evaluate won — order-dependent, and thus
        # sensitive to any incidental variation in how candidates were
        # listed. This reproduces exactly that scenario (multiple "dead"
        # candidates for one access key) across shuffled input orders and
        # repeated calls, and asserts the same candidate wins every time.
        access_key = make_access_key()
        candidates = [
            make_candidate(value="zzz-secret-candidate"),
            make_candidate(value="aaa-secret-candidate"),
            make_candidate(value="mmm-secret-candidate"),
        ]

        with mock.patch("scanner.verifier.verify_aws_key", return_value="dead"):
            selected_secrets = set()
            for _ in range(5):
                shuffled = list(candidates)
                random.shuffle(shuffled)
                pairs = pair_and_verify_aws([access_key] + shuffled)

                self.assertEqual(len(pairs), 1)
                selected_secrets.add(pairs[0]["secret_key"])

            self.assertEqual(len(selected_secrets), 1)
            # Deterministic rule: alphabetically-first extracted value wins.
            self.assertEqual(selected_secrets.pop(), "aaa-secret-candidate")

    def test_live_candidate_always_wins_regardless_of_order(self):
        access_key = make_access_key()
        candidates = [
            make_candidate(value="zzz-dead-one"),
            make_candidate(value="aaa-live-one"),
            make_candidate(value="mmm-dead-two"),
        ]

        def fake_verify(access_key_value, secret_value):
            return "live" if secret_value == "aaa-live-one" else "dead"

        with mock.patch("scanner.verifier.verify_aws_key", side_effect=fake_verify):
            for _ in range(5):
                shuffled = list(candidates)
                random.shuffle(shuffled)
                pairs = pair_and_verify_aws([access_key] + shuffled)

                self.assertEqual(pairs[0]["status"], "live")
                self.assertEqual(pairs[0]["secret_key"], "aaa-live-one")

    def test_one_transient_unverifiable_result_does_not_disturb_other_calls(self):
        # A single transient network failure on a non-winning candidate must
        # not affect which candidate is ultimately selected: the winner is
        # decided by sort order among *conclusive* (live/dead) results only.
        access_key = make_access_key()
        candidates = [
            make_candidate(value="aaa-secret-candidate"),
            make_candidate(value="zzz-secret-candidate"),
        ]

        def flaky_verify(access_key_value, secret_value):
            if secret_value == "zzz-secret-candidate":
                return "unverifiable"  # simulated transient failure
            return "dead"

        with mock.patch("scanner.verifier.verify_aws_key", side_effect=flaky_verify):
            for _ in range(5):
                pairs = pair_and_verify_aws([access_key] + candidates)
                self.assertEqual(pairs[0]["secret_key"], "aaa-secret-candidate")
                self.assertEqual(pairs[0]["status"], "dead")

    def test_single_candidate_behavior_is_unaffected(self):
        access_key = make_access_key()
        candidate = make_candidate(value="only-secret")

        with mock.patch("scanner.verifier.verify_aws_key", return_value="dead"):
            pairs = pair_and_verify_aws([access_key, candidate])

        self.assertEqual(len(pairs), 1)
        self.assertEqual(pairs[0]["secret_key"], "only-secret")
        self.assertEqual(pairs[0]["status"], "dead")


if __name__ == "__main__":
    unittest.main()
