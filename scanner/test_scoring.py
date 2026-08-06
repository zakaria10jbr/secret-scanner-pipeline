from scanner.scoring import score_finding


def test_non_production_path_scores_lower_than_src_path():
    src_result = score_finding("github_token", "unverifiable", "src/config/settings.py")
    test_result = score_finding("github_token", "unverifiable", "tests/fixtures/settings.py")

    assert test_result["score"] < src_result["score"]
    assert test_result["score"] == src_result["score"] - 30
