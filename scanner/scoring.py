# scanner/scoring.py

# --- Secret type weights ---
# Categorize by real-world impact if compromised
SECRET_TYPE_WEIGHTS = {
    # Cloud provider credentials — highest impact, broad account access
    "AWS API Key": 40,
    "AWS Access Key ID Value": 40,
    "AWS pair": 40,

    # Developer platform tokens — can lead to source code / CI compromise
    "github_token": 30,
    "Github Personal Access Token": 30,
    "Github App Token": 30,
    "Github OAuth Access Token": 30,
    "Github Refresh Token": 30,
    "Github - 2": 30,
    "Github_old": 30,
    "Githubapp - 2": 30,
    "github_api_key": 30,
    "github_oauth": 30,
    "github_tokens": 30,

    # Communication / collaboration tokens
    "Slack": 20,

    # Payment services — high impact but often scoped/restricted by default
    "Stripe": 35,
    "Stripe API Key - 1": 35,

    # Cryptographic keys — very high impact, but context-dependent
    "Asymmetric Private Key": 35,

    # Database connection strings
    "Password in URL": 30,
}

DEFAULT_TYPE_WEIGHT = 15  # fallback for any pattern not explicitly listed (e.g. generic/entropy findings)


# --- Verification status weights ---
VERIFICATION_WEIGHTS = {
    "live": 40,
    "dead": 0,
    "unverifiable": 15,  # deliberately non-trivial: uncertainty is not the same as "safe"
}


# --- Severity thresholds ---
def score_to_severity(score):
    if score >= 70:
        return "Critical"
    elif score >= 45:
        return "High"
    elif score >= 25:
        return "Medium"
    else:
        return "Low"


NON_PRODUCTION_PATH_MARKERS = ("test", "docs", "example", "spec")
NON_PRODUCTION_PATH_PENALTY = 30


def score_finding(finding_type, verification_status, file_path=None):
    type_weight = SECRET_TYPE_WEIGHTS.get(finding_type, DEFAULT_TYPE_WEIGHT)
    verification_weight = VERIFICATION_WEIGHTS.get(verification_status, VERIFICATION_WEIGHTS["unverifiable"])

    total_score = type_weight + verification_weight

    if file_path is not None and any(marker in file_path.lower() for marker in NON_PRODUCTION_PATH_MARKERS):
        total_score = max(0, total_score - NON_PRODUCTION_PATH_PENALTY)

    severity = score_to_severity(total_score)

    # Verification status can override the base severity in either direction:
    if verification_status == "dead":
        severity = "Low"  # confirmed dead: no practical exploitation risk, regardless of type
    elif verification_status == "live" and severity != "Critical":
        severity = "High"  # confirmed live: never treated as anything less than High

    return {
        "score": total_score,
        "severity": severity,
    }