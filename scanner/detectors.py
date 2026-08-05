# scanner/detectors.py

import re
import math
import yaml
import git
from collections import Counter


# ============================================================
#  PATTERN LOADING
# ============================================================

DEFAULT_PATTERNS_PATH = "config/rules-stable.yml"


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
                findings.append(secret_type)
                already_flagged_values.add(matched_value)

    # --- Entropy check ---
    for value in extract_quoted_values(line):
        if is_likely_false_positive(value):
            continue
        if value in already_flagged_values:
            continue
        entropy = shannon_entropy(value)
        if entropy > entropy_threshold and len(value) > min_length:
            findings.append(f"High entropy string (entropy={entropy:.2f})")
            already_flagged_values.add(value)

    return findings


# ============================================================
#  GIT HISTORY WALKING
# ============================================================

def scan_repo(repo_path, patterns):
    """Walk every commit in the repo, extract added lines, and check each for secrets."""
    repo = git.Repo(repo_path)
    findings_report = []

    for commit in repo.iter_commits():
        if not commit.parents:
            continue

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
                            "finding": finding,
                            "commit": commit.hexsha[:8],
                            "file": diff.b_path,
                            "line": added_line.strip(),
                        }
                        findings_report.append(result)
                        print(f"[{finding}] Commit {result['commit']} — {result['file']}: {result['line']}")

    return findings_report