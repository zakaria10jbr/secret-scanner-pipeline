# scanner/remediation.py

import json
import os
from datetime import datetime, timezone


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

def generate_report(findings, aws_pairs, filepath="reports/findings.json"):
    """Write a JSON report combining scored findings and AWS pairs."""
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_findings": len(findings) + len(aws_pairs),
        "findings": findings,
        "aws_pairs": aws_pairs,
    }

    os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    return filepath
