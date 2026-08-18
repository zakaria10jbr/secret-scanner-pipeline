# scanner/detectors.py

import os
import re
import math
import yaml
import git
from collections import Counter
from pathlib import Path

from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TaskProgressColumn,
    MofNCompleteColumn,
    TimeElapsedColumn,
)

from scanner.verifier import extract_value


def _scan_progress():
    """Build a Rich Progress instance with a spinner, animated bar, percentage,
    and item count — shared by scan_repo() and scan_current_state()."""
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
    )


# ============================================================
#  PATTERN LOADING
# ============================================================

# Resolved relative to this file's own location (not the current working directory),
# so the bundled pattern library is found regardless of where secretscan is run from.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_PATTERNS_PATH = PROJECT_ROOT / "config" / "rules-stable.yml"


def load_patterns(filepath=DEFAULT_PATTERNS_PATH, min_confidence="high"):
    """Load and filter the regex pattern library by confidence level."""
    with open(filepath, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    allowed_confidence = {"high"} if min_confidence == "high" else {"high", "medium"}

    patterns = {}
    for entry in data["patterns"]:
        p = entry["pattern"]
        if p.get("confidence") in allowed_confidence:
            patterns[p["name"]] = p["regex"]

    return patterns


# ============================================================
#  ENTROPY DETECTION
# ============================================================

def shannon_entropy(text):
    """Calculate the Shannon entropy of a string (higher = more random-looking)."""
    if not text:
        return 0
    counts = Counter(text)
    length = len(text)
    entropy = 0
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy


# ============================================================
#  FALSE POSITIVE FILTERING
# ============================================================

FALSE_POSITIVE_MARKERS = ["example", "test", "dummy", "placeholder", "your_key_here", "xxxx"]


def is_likely_false_positive(matched_text):
    """Filter out obvious placeholder/example/test values before flagging."""
    lowered = matched_text.lower()
    return any(marker in lowered for marker in FALSE_POSITIVE_MARKERS)


# ============================================================
#  COMBINED LINE-LEVEL DETECTION
# ============================================================

def extract_quoted_values(line):
    """Extract only the string values inside quotes, ignoring surrounding code syntax."""
    return re.findall(r'["\']([^"\']{8,})["\']', line)


def check_line_for_secrets(line, patterns, entropy_threshold=4.0, min_length=15):
    findings = []
    already_flagged_values = set()

    # --- Regex check ---
    for secret_type, pattern in patterns.items():
        match = re.search(pattern, line)
        if match and not is_likely_false_positive(line):
            matched_value = match.group(0)
            if matched_value not in already_flagged_values:
                findings.append({"finding": secret_type, "method": "regex"})
                already_flagged_values.add(matched_value)

    # --- Entropy check ---
    for value in extract_quoted_values(line):
        if is_likely_false_positive(value):
            continue
        if value in already_flagged_values:
            continue
        entropy = shannon_entropy(value)
        if entropy > entropy_threshold and len(value) > min_length:
            findings.append({
                "finding": f"High entropy string (entropy={entropy:.2f})",
                "method": "entropy",
            })
            already_flagged_values.add(value)

    return findings


# ============================================================
#  CURRENT-STATE (HEAD) CHECK
# ============================================================

def check_still_present(repo, file_path, matched_value):
    """Check whether matched_value still appears in file_path's content at HEAD.

    Informational only — returns False (rather than raising) for any
    lookup failure, including a deleted file or an undecodable/binary blob.
    """
    if not file_path or not matched_value:
        return False

    try:
        blob = repo.head.commit.tree / file_path
        content = blob.data_stream.read().decode("utf-8", errors="strict")
    except Exception:
        return False

    return matched_value in content


# ============================================================
#  GIT HISTORY WALKING
# ============================================================

def scan_repo(repo_path, patterns):
    """Walk every commit in the repo, extract added lines, and check each for secrets."""
    repo = git.Repo(repo_path)
    findings_report = []

    commits = list(repo.iter_commits())

    with _scan_progress() as progress:
        task = progress.add_task("Scanning commit history", total=len(commits))

        for commit in commits:
            if commit.parents:
                parent = commit.parents[0]
                diffs = parent.diff(commit, create_patch=True)

                for diff in diffs:
                    try:
                        patch_text = diff.diff.decode("utf-8", errors="ignore")
                    except Exception:
                        continue

                    for line in patch_text.split("\n"):
                        if line.startswith("+") and not line.startswith("+++"):
                            added_line = line[1:]
                            findings = check_line_for_secrets(added_line, patterns)

                            for finding in findings:
                                result = {
                                    "finding": finding["finding"],
                                    "method": finding["method"],
                                    "commit": commit.hexsha[:8],
                                    "file": diff.b_path,
                                    "line": added_line.strip(),
                                    "source": "history",
                                }
                                result["still_present"] = check_still_present(
                                    repo, result["file"], extract_value(result["line"])
                                )
                                findings_report.append(result)

            progress.advance(task)

    return findings_report


# ============================================================
#  CURRENT-STATE (HEAD) WALKING
# ============================================================

def scan_current_state(repo_path, patterns):
    """Scan every file in the repo's current working tree (HEAD) for secrets,
    independent of commit history.

    This closes the gap left by scan_repo(), which walks commit diffs and so
    never sees a repo's first commit (no parent to diff against) — a secret
    introduced only there and never touched again would otherwise be invisible.
    """
    # TEMPORARY DIAGNOSTIC INSTRUMENTATION — plain print(flush=True), not
    # routed through Rich, so output survives even if the process hangs or
    # gets killed before Rich's buffered/live output would otherwise flush.
    # Remove once the CI hang (commit-history scan completes, current-state
    # scan produces zero further output) is root-caused.
    print("[DIAG scan_current_state] entered function", flush=True)

    repo = git.Repo(repo_path)
    print("[DIAG scan_current_state] git.Repo() opened", flush=True)

    head_commit_sha = repo.head.commit.hexsha[:8]
    print(f"[DIAG scan_current_state] resolved HEAD commit: {head_commit_sha}", flush=True)

    findings_report = []

    file_paths = []
    print(f"[DIAG scan_current_state] starting os.walk({repo_path!r})", flush=True)
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d != ".git"]
        for filename in files:
            file_paths.append(os.path.join(root, filename))
    print(f"[DIAG scan_current_state] os.walk complete: {len(file_paths)} file(s): {file_paths}", flush=True)

    print("[DIAG scan_current_state] entering progress bar context", flush=True)
    with _scan_progress() as progress:
        task = progress.add_task("Scanning current-state files", total=len(file_paths))
        print("[DIAG scan_current_state] progress task created, starting file loop", flush=True)

        for file_path in file_paths:
            rel_path = os.path.relpath(file_path, repo_path).replace(os.sep, "/")
            print(f"[DIAG scan_current_state] BEGIN file: {rel_path}", flush=True)

            try:
                with open(file_path, "r", encoding="utf-8", errors="strict") as f:
                    content = f.read()
            except Exception as e:
                content = None
                print(f"[DIAG scan_current_state]   read failed "
                      f"({type(e).__name__}: {e}) — treated as skip", flush=True)

            if content is not None:
                for line in content.split("\n"):
                    findings = check_line_for_secrets(line, patterns)

                    for finding in findings:
                        findings_report.append({
                            "finding": finding["finding"],
                            "method": finding["method"],
                            "commit": head_commit_sha,
                            "file": rel_path,
                            "line": line.strip(),
                            "still_present": True,
                            "source": "current_state",
                        })

            print(f"[DIAG scan_current_state] END file: {rel_path}", flush=True)
            progress.advance(task)

    print(f"[DIAG scan_current_state] loop complete, {len(findings_report)} finding(s)", flush=True)
    return findings_report