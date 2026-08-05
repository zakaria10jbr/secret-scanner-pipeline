import tempfile
import shutil
import git


def scan_remote_repo(repo_url, patterns, scan_repo_fn):
    """
    Clone a remote Git repository into a temporary directory, scan it using the
    existing scan_repo() logic, then clean up the temporary directory afterward.

    Args:
        repo_url: HTTPS URL of the Git repository to scan (e.g. a GitHub URL).
        patterns: the loaded pattern dictionary, as returned by load_patterns().
        scan_repo_fn: the existing scan_repo() function from detectors.py,
                      passed in to avoid a circular import.

    Returns:
        The same findings list that scan_repo() normally returns.
    """
    tmp_dir = tempfile.mkdtemp(prefix="secret_scan_")
    try:
        print(f"Cloning {repo_url} into temporary directory...")
        git.Repo.clone_from(repo_url, tmp_dir)
        print("Clone complete. Starting scan...\n")

        results = scan_repo_fn(tmp_dir, patterns)
        return results

    finally:
        # Always clean up, even if the scan raised an error
        shutil.rmtree(tmp_dir, ignore_errors=True)
        print(f"\nTemporary directory removed.")