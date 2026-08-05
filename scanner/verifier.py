# scanner/verifier.py

import boto3
import requests
import re
from botocore.exceptions import ClientError, EndpointConnectionError


def verify_aws_key(access_key, secret_key):
    """Verify an AWS key pair using STS get_caller_identity (read-only, no side effects)."""
    client = boto3.client(
        "sts",
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name="us-east-1",
    )
    try:
        client.get_caller_identity()
        return "live"
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code in ("InvalidClientTokenId", "SignatureDoesNotMatch", "AccessDenied"):
            return "dead"
        return "unverifiable"
    except EndpointConnectionError:
        return "unverifiable"
    except Exception:
        return "unverifiable"

def verify_github_token(token):
    """Verify a GitHub token using the authenticated /user endpoint (read-only)."""
    headers = {"Authorization": f"token {token}"}
    try:
        response = requests.get("https://api.github.com/user", headers=headers, timeout=5)
        if response.status_code == 200:
            return "live"
        elif response.status_code == 401:
            return "dead"
        return "unverifiable"
    except requests.RequestException:
        return "unverifiable"

def extract_value(line):
    """Extract the value from a line, stripping key= and quotes where present."""
    match = re.search(r'["\']([^"\']+)["\']', line)
    if match:
        return match.group(1)
    # fallback: last whitespace-separated token (covers bare values like BARE-SECRETS)
    return line.strip().split()[-1] if line.strip() else line.strip()
def pair_and_verify_aws(findings):
    """Pair AWS Access Key IDs with candidate Secret Access Keys in the same commit+file,
    then attempt real verification on each pair. Returns a list of verified pair results."""
    grouped = {}
    for f in findings:
        key = (f["commit"], f["file"])
        grouped.setdefault(key, []).append(f)

    verified_pairs = []

    for (commit, file), group in grouped.items():
        access_keys = [f for f in group if f["finding"] == "AWS API Key"]
        candidates = [f for f in group if "High entropy" in f["finding"]]

        for ak in access_keys:
            access_key_value = extract_value(ak["line"])
            best_status = "unverifiable"
            matched_secret = None

            for candidate in candidates:
                secret_value = extract_value(candidate["line"])
                status = verify_aws_key(access_key_value, secret_value)
                if status in ("live", "dead"):
                    best_status = status
                    matched_secret = secret_value
                    if status == "live":
                        break  # found a confirmed real match, stop searching

            verified_pairs.append({
                "access_key_id": access_key_value,
                "secret_key": matched_secret,
                "status": best_status,
                "commit": commit,
                "file": file,
            })

    return verified_pairs

def verify_slack_token(token):
    """Verify a Slack token using the auth.test endpoint (read-only, purpose-built for validation)."""
    headers = {"Authorization": f"Bearer {token}"}
    try:
        response = requests.post("https://slack.com/api/auth.test", headers=headers, timeout=5)
        data = response.json()
        if data.get("ok") is True:
            return "live"
        elif data.get("error") in ("invalid_auth", "not_authed", "token_revoked"):
            return "dead"
        return "unverifiable"
    except requests.RequestException:
        return "unverifiable"


VERIFIERS = {
    "AWS API Key": verify_aws_key,
    "AWS Access Key ID Value": verify_aws_key,
    "Github Personal Access Token": verify_github_token,
    "Github App Token": verify_github_token,
    "Github OAuth Access Token": verify_github_token,
    "Github Refresh Token": verify_github_token,
    "Github - 2": verify_github_token,
    "Github_old": verify_github_token,
    "Githubapp - 2": verify_github_token,
    "github_api_key": verify_github_token,
    "github_oauth": verify_github_token,
    "github_token": verify_github_token,
    "github_tokens": verify_github_token,
    "Slack": verify_slack_token,
}


def verify_secret(secret_type, value):
    """Dispatch to the correct verifier. AWS is skipped for now (requires paired credentials)."""
    if secret_type in ("AWS API Key", "AWS Access Key ID Value"):
        return "unverifiable"  # requires a paired secret key, not yet implemented

    verifier_fn = VERIFIERS.get(secret_type)
    if verifier_fn is None:
        return "unverifiable"
    return verifier_fn(value)