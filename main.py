import argparse

from rich import box
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.rule import Rule

from scanner.detectors import load_patterns, scan_repo, scan_current_state
from scanner.verifier import verify_secret, pair_and_verify_aws, extract_value
from scanner.remote import scan_remote_repo
from scanner.scoring import score_finding
from scanner.remediation import route_remediation, generate_report
from scanner.redact import redact_value
from scanner.baseline import compute_finding_id, load_baseline, save_baseline, diff_against_baseline

console = Console()

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]

SEVERITY_STYLES = {
    "Critical": "bold red",
    "High": "dark_orange",
    "Medium": "yellow",
    "Low": "green",
}

RAW_AWS_FINDING_TYPES = ("AWS API Key", "AWS Access Key ID Value")


def print_banner():
    body = Text(justify="center")
    body.append("SECRET SCANNER\n", style="bold white")
    body.append("detect -> verify -> score -> remediate", style="cyan italic")
    console.print(Panel(body, border_style="cyan", expand=True, padding=(1, 2)))
    console.print()


def build_arg_parser():
    parser = argparse.ArgumentParser(
        prog="secret-scanner",
        description="Continuous secret scanning tool with criticality scoring and automated remediation.",
    )

    source_group = parser.add_mutually_exclusive_group(required=True)
    source_group.add_argument(
        "--url",
        help="HTTPS URL of a remote Git repository to scan (it will be cloned temporarily).",
    )
    source_group.add_argument(
        "--path",
        help="Path to a local Git repository to scan.",
    )

    parser.add_argument(
        "--patterns",
        default=None,
        help="Path to a custom pattern YAML file (defaults to config/rules-stable.yml).",
    )
    parser.add_argument(
        "--history-only",
        action="store_true",
        default=False,
        help="Skip the current-state scan and only walk commit diffs (faster, but "
             "misses secrets only present in the repository's first commit).",
    )
    parser.add_argument(
        "--show",
        action="store_true",
        default=False,
        help="Show full, unredacted secret values in output. By default, matched "
             "values are masked to prevent accidental exposure in terminal history, "
             "shared screenshots, or logs. Only use this if you specifically need to "
             "see the real value, e.g. to confirm which credential to rotate.",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        metavar="PATH",
        help="Write the JSON report to this exact path instead of the default "
             "auto-generated, timestamped filename under reports/. An explicit "
             "--output path is never subject to the 10-file retention cleanup "
             "that applies to auto-generated reports.",
    )
    parser.add_argument(
        "--summary",
        action="store_true",
        default=False,
        help="Show only the summary block, not the detailed per-severity finding "
             "tables. Useful for a quick headline check (totals, severity/"
             "verification breakdown) without scrolling past full detail tables. "
             "The JSON report is still written in full either way.",
    )
    parser.add_argument(
        "--severity",
        choices=["critical", "high", "medium", "low"],
        default=None,
        help="Only show detailed finding tables for this severity level and "
             "above (e.g. --severity high shows High and Critical only). The "
             "summary block still reports the true breakdown across all "
             "severities either way — this only limits the detail tables. "
             "The JSON report is unaffected and always contains everything.",
    )
    parser.add_argument(
        "--baseline",
        action="store_true",
        default=False,
        help="Compare this scan against the last --baseline scan of the same "
             "repo and only show full detail for findings that are new since "
             "then; findings seen before are counted but not repeated in the "
             "detail tables. Intended for repeated/automated scanning (CI/CD, "
             "scheduled scans), where re-printing every already-known finding "
             "on every run buries what actually changed. Has no effect on the "
             "JSON report, which always contains everything. After the scan, "
             "the current full set of findings is saved as the new baseline "
             "for next time.",
    )

    return parser


def clean_value(text):
    """Strip whitespace and surrounding quote noise from a matched line for clean display."""
    text = text.strip()
    if len(text) >= 2 and text[0] in "\"'" and text[-1] == text[0]:
        text = text[1:-1]
    return text


def severities_at_or_above(threshold):
    """Return the severities from SEVERITY_ORDER at or above `threshold` (a
    case-insensitive level name, e.g. "high"), using the existing
    Critical > High > Medium > Low ordering. Returns the full list unchanged
    if threshold is None or not a recognized level."""
    if not threshold:
        return list(SEVERITY_ORDER)
    normalized = threshold.strip().title()
    if normalized not in SEVERITY_ORDER:
        return list(SEVERITY_ORDER)
    cutoff = SEVERITY_ORDER.index(normalized)
    return SEVERITY_ORDER[: cutoff + 1]


def dedupe_current_state_results(results):
    """Drop current-state findings that duplicate a history finding for the same
    file + matched value, so a secret caught by both passes is only reported once."""
    history_keys = {
        (r["file"], extract_value(r["line"]))
        for r in results
        if r.get("source") == "history"
    }

    return [
        r for r in results
        if r.get("source") != "current_state"
        or (r["file"], extract_value(r["line"])) not in history_keys
    ]


def truncate(text, max_len=80):
    if len(text) > max_len:
        return text[:max_len].rstrip() + "..."
    return text


def summarize_files(files, max_shown=2):
    """Build a compact, truncated summary of unique file names, e.g.
    '.aws/credentials, bad-vars.tf, +2 more'."""
    unique_files = list(dict.fromkeys(files))  # dedupe, preserve first-seen order
    if len(unique_files) <= max_shown:
        return ", ".join(unique_files)
    shown = unique_files[:max_shown]
    remaining = len(unique_files) - max_shown
    return f"{', '.join(shown)}, +{remaining} more"


def group_findings_for_display(findings_in_group):
    """Group individual finding occurrences that share the same detected value
    so a secret repeated across many locations renders as one consolidated
    row instead of one row per occurrence (display-only — does not affect
    reports/findings.json, which still lists every occurrence).

    Occurrences are only merged when their finding type, value, verification
    status, score, and severity are already identical: the same literal
    string is sometimes flagged by two different detection rules (e.g. a
    named pattern and the generic entropy check) on one line, and those must
    stay on separate rows since they're different findings, not repeats of
    the same one.
    """
    groups = {}
    order = []
    for result in findings_in_group:
        key = (
            result["finding"],
            extract_value(result["line"]),
            result.get("verification_status", "unverifiable"),
            result["score"],
            result["severity"],
            result["action_taken"],
        )
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(result)

    return [groups[key] for key in order]


def group_aws_pairs_for_display(pairs_in_group):
    """Same consolidation as group_findings_for_display(), but keyed on the
    AWS access key + secret key pair rather than a single value: the same
    access key can pair with a different (or no) secret key depending on
    what else is co-located in its commit/file, and that changes the
    verification outcome — so the pair, not the access key alone, is what
    identifies "the same secret" here."""
    groups = {}
    order = []
    for pair in pairs_in_group:
        key = (
            pair["access_key_id"],
            pair["secret_key"],
            pair["status"],
            pair["score"],
            pair["severity"],
            pair["action_taken"],
        )
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(pair)

    return [groups[key] for key in order]


def print_summary(repo_label, pattern_count, scored_results, aws_pairs, history_only):
    severity_counts = {sev: 0 for sev in SEVERITY_ORDER}
    for result in scored_results:
        severity_counts[result["severity"]] = severity_counts.get(result["severity"], 0) + 1
    for pair in aws_pairs:
        severity_counts[pair["severity"]] = severity_counts.get(pair["severity"], 0) + 1

    verification_counts = {"live": 0, "dead": 0, "unverifiable": 0}
    for result in scored_results:
        status = result.get("verification_status", "unverifiable")
        verification_counts[status] = verification_counts.get(status, 0) + 1
    for pair in aws_pairs:
        verification_counts[pair["status"]] = verification_counts.get(pair["status"], 0) + 1

    method_counts = {"regex": 0, "entropy": 0}
    for result in scored_results:
        method = result.get("method")
        if method in method_counts:
            method_counts[method] += 1

    scan_mode = "History only (--history-only)" if history_only else "History + current-state (default)"

    severity_display = "   ".join(
        f"[{SEVERITY_STYLES[sev]}]{sev}: {severity_counts[sev]}[/{SEVERITY_STYLES[sev]}]"
        for sev in SEVERITY_ORDER
    )
    verification_display = (
        f"[green]Live: {verification_counts['live']}[/green]   "
        f"[red]Dead: {verification_counts['dead']}[/red]   "
        f"[dim]Unverifiable: {verification_counts['unverifiable']}[/dim]"
    )

    table = Table(
        title="SECRET SCANNER — SCAN SUMMARY",
        title_style="bold white",
        show_header=False,
        box=box.ROUNDED,
        border_style="cyan",
        padding=(0, 1),
    )
    table.add_column("Field", style="bold", no_wrap=True)
    table.add_column("Value", overflow="ellipsis", no_wrap=True)

    table.add_row("Repository", truncate(str(repo_label), max_len=80))
    table.add_row("Patterns loaded", f"{pattern_count} (high-confidence)")
    table.add_row("Scan mode", scan_mode)
    table.add_row(
        "Total findings",
        f"{len(scored_results) + len(aws_pairs)} "
        f"({len(scored_results)} individual + {len(aws_pairs)} AWS credential pairs)",
    )
    table.add_row(
        "Detection method",
        f"Regex-matched: {method_counts['regex']}   Entropy-only: {method_counts['entropy']}",
    )
    table.add_row("Severity breakdown", severity_display)
    table.add_row("Verification breakdown", verification_display)

    console.print(table)
    console.print(
        "[dim]Entropy-only findings carry a higher false-positive risk and "
        "should be reviewed with additional context.[/dim]"
    )
    console.print()


def print_findings_table(severity, findings_in_group, show=False):
    if not findings_in_group:
        return

    style = SEVERITY_STYLES[severity]
    table = Table(box=box.ROUNDED, border_style=style, header_style=f"bold {style}", expand=True)
    table.add_column("Finding Type", overflow="ellipsis", no_wrap=True, ratio=1, min_width=12)
    table.add_column("File", overflow="ellipsis", no_wrap=True, ratio=1, min_width=14)
    table.add_column("Value", overflow="ellipsis", no_wrap=True, ratio=1, min_width=14)
    table.add_column("Verif.", justify="center", no_wrap=True, min_width=14, max_width=14)
    table.add_column("Score", justify="right", no_wrap=True, min_width=6, max_width=6)
    table.add_column("Action", no_wrap=True, min_width=18, max_width=18)
    table.add_column("Present", justify="center", no_wrap=True, min_width=8, max_width=8)

    for group in group_findings_for_display(findings_in_group):
        representative = group[0]

        if show:
            displayed_value = clean_value(representative["line"])
        else:
            displayed_value = redact_value(extract_value(representative["line"]))

        if len(group) == 1:
            file_display = f"{representative['file']} ({representative['commit']})"
            present = "Yes" if representative.get("still_present", False) else "No"
        else:
            # scan_repo() walks commits newest-to-oldest, and current-state
            # entries are appended last, so the last-added occurrence in a
            # group is the earliest history commit for that value.
            earliest_commit = group[-1]["commit"]
            file_display = (
                f"{len(group)} locations (earliest: {earliest_commit})\n"
                f"[dim]{summarize_files(g['file'] for g in group)}[/dim]"
            )
            present = "Yes" if any(g.get("still_present", False) for g in group) else "No"

        table.add_row(
            representative["finding"],
            file_display,
            displayed_value,
            representative.get("verification_status", "unverifiable").upper(),
            str(representative["score"]),
            representative["action_taken"],
            present,
        )

    console.print(table)
    console.print()


def print_aws_pairs_table(severity, pairs_in_group, show=False):
    if not pairs_in_group:
        return

    style = SEVERITY_STYLES[severity]
    console.print(Rule(f"AWS Credential Pairs ({severity})", style=style, characters="-"))

    table = Table(box=box.ROUNDED, border_style=style, header_style=f"bold {style}", expand=True)
    table.add_column("File", overflow="ellipsis", no_wrap=True, ratio=1, min_width=14)
    table.add_column("Access Key", overflow="ellipsis", no_wrap=True, ratio=1, min_width=14)
    table.add_column("Secret Key", overflow="ellipsis", no_wrap=True, ratio=1, min_width=14)
    table.add_column("Verif.", justify="center", no_wrap=True, min_width=14, max_width=14)
    table.add_column("Score", justify="right", no_wrap=True, min_width=6, max_width=6)
    table.add_column("Action", no_wrap=True, min_width=18, max_width=18)
    table.add_column("Present", justify="center", no_wrap=True, min_width=8, max_width=8)

    for group in group_aws_pairs_for_display(pairs_in_group):
        representative = group[0]

        if representative["access_key_id"]:
            access_key = clean_value(representative["access_key_id"])
            if not show:
                access_key = redact_value(access_key)
        else:
            access_key = "unknown"

        if representative["secret_key"]:
            secret_key = clean_value(representative["secret_key"])
            if not show:
                secret_key = redact_value(secret_key)
        else:
            secret_key = "none matched"

        if len(group) == 1:
            file_display = f"{representative['file']} ({representative['commit']})"
            present = "Yes" if representative.get("still_present", False) else "No"
        else:
            earliest_commit = group[-1]["commit"]
            file_display = (
                f"{len(group)} locations (earliest: {earliest_commit})\n"
                f"[dim]{summarize_files(g['file'] for g in group)}[/dim]"
            )
            present = "Yes" if any(g.get("still_present", False) for g in group) else "No"

        table.add_row(
            file_display,
            access_key,
            secret_key,
            representative["status"].upper(),
            str(representative["score"]),
            representative["action_taken"],
            present,
        )

    console.print(table)
    console.print()


def main():
    print_banner()

    parser = build_arg_parser()
    args = parser.parse_args()

    if args.patterns:
        patterns = load_patterns(args.patterns)
    else:
        patterns = load_patterns()

    scan_fns = [scan_repo] if args.history_only else [scan_repo, scan_current_state]

    if args.url:
        results = scan_remote_repo(args.url, patterns, scan_fns)
    else:
        results = []
        for scan_fn in scan_fns:
            results.extend(scan_fn(args.path, patterns))

    if not args.history_only:
        results = dedupe_current_state_results(results)

    # --- Verification (silent) ---
    for result in results:
        secret_type = result["finding"]
        if secret_type in RAW_AWS_FINDING_TYPES:
            continue
        status = verify_secret(secret_type, result["line"])
        result["verification_status"] = status

    # --- AWS credential pairing and verification (silent) ---
    aws_pairs = pair_and_verify_aws(results)

    # --- Scoring (silent) ---
    for result in results:
        if result["finding"] in RAW_AWS_FINDING_TYPES:
            continue  # already scored separately via AWS pairing
        status = result.get("verification_status", "unverifiable")
        scored = score_finding(result["finding"], status, result["file"])
        result["score"] = scored["score"]
        result["severity"] = scored["severity"]

    for pair in aws_pairs:
        pair["finding"] = "AWS pair"
        scored = score_finding("AWS pair", pair["status"], pair["file"])
        pair["score"] = scored["score"]
        pair["severity"] = scored["severity"]

    # --- Remediation routing (silent) ---
    for result in results:
        if result["finding"] in RAW_AWS_FINDING_TYPES:
            continue
        remediation_result = route_remediation(result)
        result.update(remediation_result)

    for pair in aws_pairs:
        remediation_result = route_remediation(pair)
        pair.update(remediation_result)

    scored_results = [r for r in results if "severity" in r]

    repo_label = args.url if args.url else args.path

    # --- Baseline diff (silent) ---
    # Finding IDs are computed from fully-enriched data (post scoring/
    # remediation) so they line up with what's about to be displayed/saved.
    new_finding_ids = None
    current_finding_ids = None
    baseline_new_count = 0
    baseline_previously_seen_count = 0

    if args.baseline:
        previous_finding_ids = load_baseline(repo_label)
        new_findings, previously_seen_findings, current_finding_ids = diff_against_baseline(
            scored_results, aws_pairs, previous_finding_ids
        )
        new_finding_ids = current_finding_ids - previous_finding_ids
        baseline_new_count = len(new_findings)
        baseline_previously_seen_count = len(previously_seen_findings)

    # --- Output: one pass, fully resolved ---
    print_summary(repo_label, len(patterns), scored_results, aws_pairs, args.history_only)

    if args.baseline:
        console.print(
            f"[dim]Baseline comparison:[/dim] {baseline_new_count} new findings, "
            f"{baseline_previously_seen_count} previously seen "
            f"(suppressed from detailed output)"
        )
        console.print()

    if not args.summary:
        displayed_severities = severities_at_or_above(args.severity)
        hidden_severities = [s for s in SEVERITY_ORDER if s not in displayed_severities]

        if hidden_severities:
            level_word = "level" if len(hidden_severities) == 1 else "levels"
            console.print(
                f"[dim]Showing {args.severity.title()} and above only "
                f"({len(hidden_severities)} severity {level_word} hidden: "
                f"{', '.join(hidden_severities)})[/dim]"
            )
            console.print()

        for severity in SEVERITY_ORDER:
            if severity not in displayed_severities:
                continue

            findings_in_group = [r for r in scored_results if r["severity"] == severity]
            pairs_in_group = [p for p in aws_pairs if p["severity"] == severity]

            if args.baseline:
                findings_in_group = [
                    r for r in findings_in_group if compute_finding_id(r) in new_finding_ids
                ]
                pairs_in_group = [
                    p for p in pairs_in_group if compute_finding_id(p) in new_finding_ids
                ]

            if not findings_in_group and not pairs_in_group:
                continue

            style = SEVERITY_STYLES[severity]
            console.rule(f"[{style}]{severity.upper()}[/{style}]", style=style)

            print_findings_table(severity, findings_in_group, show=args.show)
            print_aws_pairs_table(severity, pairs_in_group, show=args.show)

    # The JSON report always contains full, unredacted values regardless of
    # --show — redaction is a terminal-display concern only, not applied here.
    report_path = generate_report(results, aws_pairs, filepath=args.output, redact=False)
    console.print(f"[dim]Report written to:[/dim] {report_path}")
    if args.output is None:
        location_note = (
            "reports/ is gitignored, but handle it accordingly: don't commit "
            "it or share it without care. Only the 10 most recent reports "
            "are kept; older ones are deleted automatically."
        )
    else:
        location_note = (
            "this is an explicit --output path, so handle it accordingly "
            "(don't commit or share it without care) and note it's exempt "
            "from the usual reports/ retention cleanup — it won't be "
            "auto-deleted."
        )
    console.print(
        "[yellow]Note:[/yellow] this file contains real, unredacted secret "
        f"values (regardless of --show) — {location_note}"
    )

    if args.baseline:
        baseline_path = save_baseline(repo_label, current_finding_ids)
        console.print(f"[dim]Baseline updated:[/dim] {baseline_path}")


if __name__ == "__main__":
    main()
