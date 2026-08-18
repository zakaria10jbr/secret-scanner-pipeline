# scanner/remediation.py

import glob
import json
import os
from datetime import datetime, timezone

from scanner.redact import redact_value
from scanner.verifier import extract_value


# ============================================================
#  REMEDIATION TEMPLATES
# ============================================================

REMEDIATION_TEMPLATES = {
    "aws": {
        "immediate_actions": [
            "1. Deactivate the exposed IAM access key immediately via the AWS Console or CLI (aws iam update-access-key --status Inactive).",
            "2. Review CloudTrail logs for any activity performed with the exposed key since it was committed.",
            "3. Delete the deactivated key once you've confirmed no legitimate workloads depend on it.",
        ],
        "rotation_guidance": "Create a new access key pair, update all services/config to use it, then delete the old key via IAM.",
        "docs_url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html",
    },
    "github": {
        "immediate_actions": [
            "1. Revoke the exposed token immediately from GitHub Settings > Developer settings > Personal access tokens.",
            "2. Check the token's recent activity in the GitHub audit log for unauthorized access.",
            "3. Purge the token from git history if it's still reachable in the repo.",
        ],
        "rotation_guidance": "Generate a new personal access token with the minimum required scopes, update every consumer, then revoke the old token.",
        "docs_url": "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens",
    },
    "slack": {
        "immediate_actions": [
            "1. Revoke the exposed token from the Slack app's OAuth & Permissions page immediately.",
            "2. Review the app's access logs for unusual activity.",
            "3. Reinstall the app to the workspace to force new credentials.",
        ],
        "rotation_guidance": "Reinstall or regenerate the app's token from the Slack API dashboard, then update any services using the old token.",
        "docs_url": "https://api.slack.com/authentication/rotation",
    },
    "stripe": {
        "immediate_actions": [
            "1. Roll the exposed API key immediately from the Stripe Dashboard > Developers > API keys.",
            "2. Review the Stripe Dashboard's request logs for unauthorized usage.",
            "3. Update all services using the old key with the newly generated one.",
        ],
        "rotation_guidance": "Roll the key from the Stripe Dashboard, which issues a replacement while keeping the old key valid briefly for a safe cutover.",
        "docs_url": "https://docs.stripe.com/keys#roll-keys",
    },
    "generic": {
        "immediate_actions": [
            "1. Treat the exposed value as compromised and revoke or invalidate it via its issuing system.",
            "2. Review any available access/audit logs for unauthorized use since exposure.",
            "3. Purge the value from git history and confirm it's no longer reachable.",
        ],
        "rotation_guidance": "Regenerate the credential through its issuing system and update all consumers before revoking the old value.",
        "docs_url": "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password",
    },
}


# ============================================================
#  CATEGORY MATCHING
# ============================================================

def get_remediation_advice(finding_type):
    """Map a raw finding type to a remediation template via simple keyword matching."""
    lowered = finding_type.lower()

    if "aws" in lowered:
        category = "aws"
    elif "github" in lowered:
        category = "github"
    elif "slack" in lowered:
        category = "slack"
    elif "stripe" in lowered:
        category = "stripe"
    else:
        category = "generic"

    return {"category": category, **REMEDIATION_TEMPLATES[category]}


# ============================================================
#  SEVERITY -> ACTION ROUTING
# ============================================================

SEVERITY_ACTIONS = {
    "Critical": "alert_and_advise",
    "High": "alert_and_advise",
    "Medium": "logged_for_digest",
    "Low": "logged_only",
}


def route_remediation(finding):
    """Route a scored finding to a remediation action based on its severity."""
    action_taken = SEVERITY_ACTIONS.get(finding["severity"], "logged_only")

    result = {"action_taken": action_taken}
    if action_taken == "alert_and_advise":
        result["remediation"] = get_remediation_advice(finding["finding"])

    return result


# ============================================================
#  REPORT GENERATION
# ============================================================

# Reports contain real, unredacted secrets by default (see generate_report()'s
# redact param) — capping how many accumulate on disk is a security measure,
# not just tidiness. Adjust this to change how many are kept.
DEFAULT_REPORT_RETENTION = 10


def cleanup_old_reports(reports_dir="reports", keep=DEFAULT_REPORT_RETENTION):
    """Delete all but the `keep` most recent findings_*.json report files in
    reports_dir. Filenames sort chronologically because of their
    findings_YYYY-MM-DD_HHMMSS.json format, so a plain name sort is enough —
    no need to parse timestamps or check file mtimes. Safe to call when
    reports_dir has fewer than `keep` files (nothing gets deleted)."""
    report_files = sorted(glob.glob(os.path.join(reports_dir, "findings_*.json")))

    excess = report_files if keep <= 0 else report_files[:-keep]

    for filepath in excess:
        try:
            os.remove(filepath)
        except OSError:
            pass


def _redact_finding_for_report(finding):
    """Return a copy of a finding dict with its matched value masked, leaving
    every other field (type, file, commit, score, severity, ...) untouched."""
    if "line" not in finding:
        return finding
    redacted = dict(finding)
    redacted["line"] = redact_value(extract_value(finding["line"]))
    return redacted


def _redact_aws_pair_for_report(pair):
    """Return a copy of an AWS pair dict with its access/secret key masked."""
    redacted = dict(pair)
    if redacted.get("access_key_id"):
        redacted["access_key_id"] = redact_value(redacted["access_key_id"])
    if redacted.get("secret_key"):
        redacted["secret_key"] = redact_value(redacted["secret_key"])
    return redacted


def generate_report(findings, aws_pairs, filepath=None, redact=False):
    """Write a JSON report combining scored findings and AWS pairs.

    redact=True masks matched secret values in the written copies only —
    the findings/aws_pairs passed in are never mutated, so callers that
    still need the real values afterward are unaffected.

    filepath defaults to a fresh, timestamped path under reports/ each call
    (findings_YYYY-MM-DD_HHMMSS.json), so successive scans don't overwrite
    each other, and only the DEFAULT_REPORT_RETENTION most recent files in
    that case are kept afterward — see cleanup_old_reports(). Pass an
    explicit filepath (e.g. via --output) to write to a specific location
    instead; explicit paths are never subject to retention cleanup, since
    they're deliberately-named files outside the normal reports/ rotation.
    """
    generated_at = datetime.now(timezone.utc)

    using_default_filepath = filepath is None
    if using_default_filepath:
        timestamp = generated_at.strftime("%Y-%m-%d_%H%M%S")
        filepath = f"reports/findings_{timestamp}.json"

    if redact:
        findings = [_redact_finding_for_report(f) for f in findings]
        aws_pairs = [_redact_aws_pair_for_report(p) for p in aws_pairs]

    report = {
        "generated_at": generated_at.isoformat(),
        "total_findings": len(findings) + len(aws_pairs),
        "findings": findings,
        "aws_pairs": aws_pairs,
    }

    os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    # Only prune once the new report is safely on disk — never delete
    # anything if the write above failed — and only for auto-generated
    # paths; an explicit filepath is never touched by retention cleanup.
    if using_default_filepath:
        cleanup_old_reports(reports_dir=os.path.dirname(filepath) or ".")

    return filepath
