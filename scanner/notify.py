# scanner/notify.py
#
# GitHub Issue notification for Critical/High findings. Kept separate from
# scanner/remediation.py (which is otherwise pure local logic: templates,
# severity routing, JSON report generation) for the same reason
# scanner/verifier.py is its own module — this is the one thing here that
# makes outbound network calls to a third-party API, with its own failure
# modes (auth, rate limiting, network errors) that must never be allowed
# to crash or block the underlying scan.

import re

import git
import requests

GITHUB_API_TIMEOUT = 10


def _match_github_slug(url):
    """Extract 'owner/repo' from a GitHub remote/clone URL, handling both
    HTTPS (https://github.com/owner/repo.git) and SSH
    (git@github.com:owner/repo.git) forms. Returns None if the URL isn't
    a recognizable github.com URL."""
    if not url:
        return None
    match = re.search(r"github\.com[:/]{1,2}([^/]+)/([^/.]+?)(?:\.git)?/?$", url)
    if not match:
        return None
    return f"{match.group(1)}/{match.group(2)}"


def detect_github_repo(args):
    """Best-effort detection of the 'owner/repo' GitHub slug for the repo
    being scanned, used as the --notify-github issue-creation target when
    --github-repo isn't explicitly given.

    For a --url scan, the URL the user already gave us is parsed directly
    (no extra lookup needed). For a --path scan, the local repo's 'origin'
    remote is checked instead.

    Returns None if detection isn't possible — a non-GitHub remote, a
    local repo with no configured 'origin', or any lookup failure — in
    which case the caller must fall back to requiring --github-repo
    explicitly. This is best-effort convenience, not a guaranteed lookup.
    """
    if args.url:
        return _match_github_slug(args.url)

    try:
        repo = git.Repo(args.path)
        remote_url = repo.remotes.origin.url
    except Exception:
        return None

    return _match_github_slug(remote_url)


def _build_issue_body(finding):
    """Build a metadata-only issue body: file, commit, verification status,
    score, and remediation advice. Deliberately never includes the actual
    matched secret value (or the raw 'line'/'access_key_id'/'secret_key'
    fields that could contain or imply it) — a GitHub Issue is typically
    far more widely visible than the tool's own JSON report, so leaking a
    real credential into one would defeat the purpose of redaction
    elsewhere in the tool.
    """
    verification_status = finding.get("verification_status") or finding.get("status", "unverifiable")

    lines = [
        f"**File:** `{finding.get('file', 'unknown')}`",
        f"**Commit:** `{finding.get('commit', 'unknown')}`",
        f"**Verification status:** {verification_status.upper()}",
        f"**Score:** {finding.get('score', 'n/a')}",
        "",
    ]

    remediation = finding.get("remediation")
    if remediation:
        lines.append("### Remediation")
        lines.append("")
        lines.append("**Immediate actions:**")
        for action in remediation.get("immediate_actions", []):
            lines.append(f"- {action}")
        lines.append("")
        lines.append(f"**Rotation guidance:** {remediation.get('rotation_guidance', '')}")
        lines.append(f"**Docs:** {remediation.get('docs_url', '')}")
        lines.append("")

    lines.append(
        "_Filed automatically by secretscan. The matched secret value is "
        "intentionally omitted from this issue — see the tool's JSON "
        "report (not committed to version control) for the real value._"
    )

    return "\n".join(lines)


def create_github_issue(finding, repo_owner, repo_name, github_token):
    """Create a GitHub Issue for a Critical/High finding via the REST API.

    Returns the created issue's HTML URL on success, or None on ANY
    failure — network error, auth failure, rate limit, unexpected response
    shape. Issue creation is a best-effort notification, never something
    that should crash or block the underlying scan, so every failure mode
    here is swallowed rather than raised.
    """
    finding_type = finding.get("finding", "Unknown")
    file_path = finding.get("file", "unknown")
    severity = finding.get("severity", "Unknown")

    title = f"[secretscan] {severity} secret detected: {finding_type} in {file_path}"
    body = _build_issue_body(finding)

    url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/issues"
    headers = {
        "Authorization": f"token {github_token}",
        "Accept": "application/vnd.github+json",
    }

    try:
        response = requests.post(
            url,
            headers=headers,
            json={"title": title, "body": body},
            timeout=GITHUB_API_TIMEOUT,
        )
        if response.status_code != 201:
            return None
        return response.json().get("html_url")
    except Exception:
        return None
