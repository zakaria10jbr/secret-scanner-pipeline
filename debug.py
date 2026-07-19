import git

repo = git.Repo(".")

for commit in repo.iter_commits():
    print(f"Commit: {commit.hexsha[:8]} — {commit.message.strip()}")
    if not commit.parents:
        print("  (no parent, skipping)")
        continue

    parent = commit.parents[0]
    diffs = parent.diff(commit, create_patch=True)
    print(f"  Found {len(diffs)} changed file(s)")

    for diff in diffs:
        patch_text = diff.diff.decode("utf-8", errors="ignore")
        print(f"  --- {diff.b_path} ---")
        print(patch_text)