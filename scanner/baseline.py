# scanner/baseline.py
#
# Baseline / incremental-scan support: lets repeated scans of the same repo
# (e.g. a scheduled or on-push CI run) recognize which findings were already
# reported last time, so only genuinely new findings need full attention.

import hashlib
import json
import os
from datetime import datetime, timezone

from scanner.verifier import extract_value

BASELINE_DIR = "baselines"


def compute_finding_id(finding):
    """Compute a stable SHA-256-based identifier (truncated to 16 hex chars)
    for a finding, so the same secret is recognized as "the same" across
    scans regardless of list order.

    AWS credential pairs (as produced by pair_and_verify_aws()) have no
    single "line" to pull a matched value from, so they're identified by
    their file, commit, access key, and secret key instead; everything else
    is identified by its finding type, file, commit, and the clean matched
    value (via extract_value(), the same extraction used for display).
    """
    if "access_key_id" in finding:
        parts = [
            finding.get("file") or "",
            finding.get("commit") or "",
            finding.get("access_key_id") or "",
            finding.get("secret_key") or "",
        ]
    else:
        parts = [
            finding.get("finding") or "",
            finding.get("file") or "",
            finding.get("commit") or "",
            extract_value(finding.get("line") or ""),
        ]

    digest_input = "\x1f".join(parts)
    return hashlib.sha256(digest_input.encode("utf-8")).hexdigest()[:16]


def get_baseline_path(repo_identifier):
    """Return the baseline file path for a given repo identifier (a --url or
    --path value), creating the baselines/ directory if it doesn't exist yet."""
    os.makedirs(BASELINE_DIR, exist_ok=True)
    repo_hash = hashlib.sha256(str(repo_identifier).encode("utf-8")).hexdigest()[:16]
    return os.path.join(BASELINE_DIR, f"{repo_hash}.json")


def load_baseline(repo_identifier):
    """Return the set of finding IDs from the last scan of this repo, or an
    empty set if no baseline exists yet."""
    path = get_baseline_path(repo_identifier)
    if not os.path.exists(path):
        return set()

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return set()

    return set(data.get("finding_ids", []))


def save_baseline(repo_identifier, all_finding_ids):
    """Write the current scan's complete finding-ID set plus a timestamp,
    overwriting any previous baseline for this repo. Returns the path
    written to."""
    path = get_baseline_path(repo_identifier)
    data = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "finding_ids": sorted(all_finding_ids),
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    return path


def diff_against_baseline(current_findings, current_aws_pairs, previous_ids):
    """Compare this scan's findings + AWS pairs against the previous
    baseline's finding-ID set.

    Returns (new_findings, previously_seen_findings, current_ids):
      - new_findings: findings/pairs whose ID wasn't in previous_ids
      - previously_seen_findings: findings/pairs whose ID was already in
        previous_ids (both lists mix regular findings and AWS pairs,
        preserving their relative order within each source list)
      - current_ids: the complete finding-ID set for this scan, ready to be
        passed to save_baseline() as the next baseline
    """
    new_findings = []
    previously_seen_findings = []
    current_ids = set()

    for finding in list(current_findings) + list(current_aws_pairs):
        finding_id = compute_finding_id(finding)
        current_ids.add(finding_id)
        if finding_id in previous_ids:
            previously_seen_findings.append(finding)
        else:
            new_findings.append(finding)

    return new_findings, previously_seen_findings, current_ids
