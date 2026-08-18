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

def verify_gitlab_token(token):
    """Verify a GitLab token using the authenticated /user endpoint (read-only)."""
    headers = {"PRIVATE-TOKEN": token}
    try:
        response = requests.get("https://gitlab.com/api/v4/user", headers=headers, timeout=5)
        if response.status_code == 200:
            return "live"
        elif response.status_code == 401:
            return "dead"
        return "unverifiable"
    except requests.RequestException:
        return "unverifiable"

def verify_discord_bot_token(token):
    """Verify a Discord bot token using the authenticated /users/@me endpoint (read-only)."""
    headers = {"Authorization": token}
    try:
        response = requests.get("https://discord.com/api/v10/users/@me", headers=headers, timeout=5)
        if response.status_code == 200:
            return "live"
        elif response.status_code == 401:
            return "dead"
        return "unverifiable"
    except requests.RequestException:
        return "unverifiable"

def verify_discord_webhook(webhook_url):
    """Verify a Discord webhook by GETing the self-contained webhook URL (read-only)."""
    try:
        response = requests.get(webhook_url, timeout=5)
        if response.status_code == 200:
            return "live"
        elif response.status_code in (401, 404):
            return "dead"
        return "unverifiable"
    except requests.RequestException:
        return "unverifiable"

def verify_dropbox_token(token):
    """Verify a Dropbox token using the authenticated get_current_account endpoint (read-only)."""
    headers = {"Authorization": f"Bearer {token}"}
    try:
        response = requests.post(
            "https://api.dropboxapi.com/2/users/get_current_account",
            headers=headers,
            timeout=5,
        )
        if response.status_code == 200:
            return "live"
        elif response.status_code == 401:
            return "dead"
        return "unverifiable"
    except requests.RequestException:
        return "unverifiable"

def verify_mailchimp_key(api_key):
    """Verify a Mailchimp API key using the ping endpoint on its embedded data center (read-only)."""
    if "-" not in api_key:
        return "unverifiable"
    datacenter = api_key.rsplit("-", 1)[-1]
    if not datacenter or not re.fullmatch(r"[a-z0-9]+", datacenter):
        return "unverifiable"
    try:
        response = requests.get(
            f"https://{datacenter}.api.mailchimp.com/3.0/ping",
            auth=("anystring", api_key),
            timeout=5,
        )
        if response.status_code == 200:
            return "live"
        elif response.status_code == 401:
            return "dead"
        return "unverifiable"
    except requests.RequestException:
        return "unverifiable"

def verify_google_api_key(api_key):
    """Verify a Google API key using the API Discovery Service (safe, read-only, low-privilege)."""
    try:
        response = requests.get(
            "https://www.googleapis.com/discovery/v1/apis",
            params={"key": api_key},
            timeout=5,
        )
        if response.status_code == 200:
            return "live"
        elif response.status_code in (400, 403):
            return "dead"
        return "unverifiable"
    except requests.RequestException:
        return "unverifiable"

def verify_shopify_key(api_key):
    """Always returns "unverifiable": Shopify's API is scoped per-shop and requires a
    shop-specific domain (e.g. "my-shop.myshopify.com") as part of the request URL. Detection
    only captures the key itself, with no paired shop domain available the way AWS's two-part
    credential is paired via pair_and_verify_aws(), so there is no real endpoint to call. Do not
    guess or hardcode a shop domain to force a check."""
    return "unverifiable"

def extract_value(line):
    """Extract the value from a line, stripping key= and quotes where present."""
    match = re.search(r'["\']([^"\']+)["\']', line)
    if match:
        return match.group(1)
    # fallback: last whitespace-separated token (covers bare values like BARE-SECRETS)
    if not line.strip():
        return line.strip()
    value = line.strip().split()[-1]
    # No matched quote pair was found above, so any quote character still
    # attached here is stray, unmatched punctuation (e.g. a mangled/corrupted
    # source line with a trailing quote and no opening one) rather than part
    # of the value itself — strip it so the same underlying secret doesn't
    # get treated as a different value just because of leftover punctuation.
    return value.strip("\"'")
def _candidate_sort_key(candidate):
    """Deterministic ordering for AWS secret-key candidates that share a
    commit+file with an access key, so pairing always considers them in the
    same order on every run — regardless of any incidental variation in the
    order findings were detected/appended in.

    Finding dicts don't currently track a source line number, so this sorts
    by the candidate's own extracted value (alphabetically) as the primary
    key, falling back to its finding/pattern name to break ties between two
    candidates that happen to share an identical value.
    """
    return (extract_value(candidate.get("line", "")), candidate.get("finding", ""))


def _select_best_aws_candidate(access_key_value, candidates):
    """Verify an access key against each candidate secret key (in a fixed,
    deterministic order) and return (status, matched_secret) for the best
    match found.

    A confirmed "live" match anywhere wins immediately. Otherwise, the
    *first* candidate (in sorted order) that verifies "dead" is kept — and
    is never overwritten by a later "dead" result — so the outcome depends
    only on the fixed candidate ordering, not on which of several live
    network calls happens to succeed or time out on any given run. Without
    this "first dead wins" rule, a transient failure on an earlier
    candidate (mapped to "unverifiable") would let a later candidate's
    "dead" result silently take its place, changing the selected secret_key
    from one run to the next even though nothing about the repo changed.
    """
    best_status = "unverifiable"
    matched_secret = None

    for candidate in sorted(candidates, key=_candidate_sort_key):
        secret_value = extract_value(candidate["line"])
        status = verify_aws_key(access_key_value, secret_value)
        if status == "live":
            return "live", secret_value  # confirmed live match: stop searching immediately
        if status == "dead" and best_status != "dead":
            best_status = "dead"
            matched_secret = secret_value

    return best_status, matched_secret


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
        candidates = [
            f for f in group
            if "High entropy" in f["finding"]
            or (
                "aws" in f["finding"].lower()
                and f["finding"] not in ("AWS API Key", "AWS Access Key ID Value")
            )
        ]

        for ak in access_keys:
            access_key_value = extract_value(ak["line"])
            best_status, matched_secret = _select_best_aws_candidate(access_key_value, candidates)

            verified_pairs.append({
                "access_key_id": access_key_value,
                "secret_key": matched_secret,
                "status": best_status,
                "commit": commit,
                "file": file,
                # Reuse the access key finding's own still_present value (computed via
                # check_still_present() in scan_repo() against the same file/value) rather
                # than re-deriving it here — the repo may already be cleaned up by the
                # time pair_and_verify_aws() runs for a --url scan.
                "still_present": ak.get("still_present", False),
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


def verify_stripe_key(api_key):
    """Verify a Stripe API key using the balance endpoint (read-only, purpose-built for validation)."""
    try:
        response = requests.get("https://api.stripe.com/v1/balance", auth=(api_key, ""), timeout=5)
        if response.status_code == 200:
            return "live"
        elif response.status_code == 401:
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
    "Gitlabv2": verify_gitlab_token,
    "Dropbox": verify_dropbox_token,
    "dropbox_oauth_bearer": verify_dropbox_token,
    "MailChimp API Key": verify_mailchimp_key,
    "mailchimp": verify_mailchimp_key,
    "Google API Key": verify_google_api_key,
    "google_maps_api_key": verify_google_api_key,
    "Shopify access token": verify_shopify_key,
    "Shopify custom app access token": verify_shopify_key,
    "Shopify private app access token": verify_shopify_key,
    "Shopify shared secret": verify_shopify_key,
    "Discordbottoken - 1": verify_discord_bot_token,
    "Discordbottoken - 2": verify_discord_bot_token,
    "Discord Webhook": verify_discord_webhook,
    "Discordwebhook": verify_discord_webhook,
    "Slack": verify_slack_token,
    "Stripe": verify_stripe_key,
    "Stripe API Key - 1": verify_stripe_key,
}


def verify_secret(secret_type, value):
    """Dispatch to the correct verifier. AWS is skipped for now (requires paired credentials)."""
    if secret_type in ("AWS API Key", "AWS Access Key ID Value"):
        return "unverifiable"  # requires a paired secret key, not yet implemented

    verifier_fn = VERIFIERS.get(secret_type)
    if verifier_fn is None:
        return "unverifiable"
    return verifier_fn(value)