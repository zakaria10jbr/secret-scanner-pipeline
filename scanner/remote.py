import tempfile
import shutil
import git


def scan_remote_repo(repo_url, patterns, scan_fns):
    """
    Clone a remote Git repository into a temporary directory, run each scan
    function in scan_fns against it while it's still on disk, then clean up
    the temporary directory afterward.

    Args:
        repo_url: HTTPS URL of the Git repository to scan (e.g. a GitHub URL).
        patterns: the loaded pattern dictionary, as returned by load_patterns().
        scan_fns: list of scan functions from detectors.py (e.g. scan_repo,
                  scan_current_state), each called as scan_fn(tmp_dir, patterns),
                  passed in to avoid a circular import.

    Returns:
        The concatenated findings lists from every function in scan_fns.
    """
    tmp_dir = tempfile.mkdtemp(prefix="secret_scan_")
    try:
        print(f"Cloning {repo_url} into temporary directory...")
        git.Repo.clone_from(repo_url, tmp_dir)
        print("Clone complete. Starting scan...\n")

        results = []
        for scan_fn in scan_fns:
            results.extend(scan_fn(tmp_dir, patterns))
        return results

    finally:
        # Always clean up, even if the scan raised an error
        shutil.rmtree(tmp_dir, ignore_errors=True)
        print(f"\nTemporary directory removed.")