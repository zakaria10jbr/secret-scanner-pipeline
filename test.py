import git
import re
import math
from collections import Counter

# ---- our detectors from before ----
patterns = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "GitHub Token": r"ghp_[A-Za-z0-9]{36}",
}

def shannon_entropy(text):
    if not text:
        return 0
    counts = Counter(text)
    length = len(text)
    entropy = 0
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy

def check_line_for_secrets(line):
    findings = []
    for secret_type, pattern in patterns.items():
        if re.search(pattern, line):
            findings.append(secret_type)

    entropy = shannon_entropy(line.strip())
    if entropy > 4.0 and len(line.strip()) > 15:
        findings.append(f"High entropy string (entropy={entropy:.2f})")

    return findings

# ---- walk the repo, pull added lines, run detectors ----
repo = git.Repo(".")

for commit in repo.iter_commits():
    if not commit.parents:
        continue

    parent = commit.parents[0]
    diffs = parent.diff(commit, create_patch=True)

    for diff in diffs:
        patch_text = diff.diff.decode("utf-8", errors="ignore")

        for line in patch_text.split("\n"):
            if line.startswith("+") and not line.startswith("+++"):
                added_line = line[1:]  # strip the leading '+'
                findings = check_line_for_secrets(added_line)

                for finding in findings:
                    print(f"[{finding}] Commit {commit.hexsha[:8]} — {diff.b_path}: {added_line.strip()}")