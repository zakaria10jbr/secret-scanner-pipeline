import argparse
import sys

from colorama import init as colorama_init, Fore, Style

from scanner.detectors import load_patterns, scan_repo
from scanner.verifier import verify_secret, pair_and_verify_aws
from scanner.remote import scan_remote_repo
from scanner.scoring import score_finding
from scanner.remediation import route_remediation, generate_report

colorama_init()

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]

SEVERITY_COLORS = {
    "Critical": Fore.LIGHTRED_EX,
    "High": Fore.RED,
    "Medium": Fore.YELLOW,
    "Low": Fore.GREEN,
}

RAW_AWS_FINDING_TYPES = ("AWS API Key", "AWS Access Key ID Value")


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
        "--min-confidence",
        choices=["high", "medium"],
        default="high",
        help="Minimum pattern confidence level to use for detection (default: high).",
    )

    return parser


def clean_value(text):
    """Strip whitespace and surrounding quote noise from a matched line for clean display."""
    text = text.strip()
    if len(text) >= 2 and text[0] in "\"'" and text[-1] == text[0]:
        text = text[1:-1]
    return text


def truncate(text, max_len=80):
    if len(text) > max_len:
        return text[:max_len].rstrip() + "..."
    return text


def colorize(text, severity):
    color = SEVERITY_COLORS.get(severity, "")
    return f"{color}{text}{Style.RESET_ALL}"


def print_section_header(severity):
    print("=" * 60)
    print(colorize(severity.upper(), severity))
    print("=" * 60)


def print_finding(finding_type, severity, file_path, commit, value_line, verification_status, score, action_taken):
    print(f"{colorize(f'[{severity.upper()}]', severity)} {finding_type}")
    print(f"  File:         {file_path} (commit {commit})")
    print(f"  Value:        {truncate(clean_value(value_line))}")
    print(f"  Verification: {verification_status.upper()}")
    print(f"  Score:        {score} points")
    print(f"  Action:       {action_taken}")
    print()


def print_aws_pair(severity, file_path, commit, access_key, secret_key, verification_status, score, action_taken):
    print(f"{colorize(f'[{severity.upper()}]', severity)} AWS pair")
    print(f"  File:         {file_path} (commit {commit})")
    print(f"  Access Key:   {truncate(clean_value(access_key)) if access_key else 'unknown'}")
    print(f"  Secret Key:   {truncate(clean_value(secret_key)) if secret_key else 'none matched'}")
    print(f"  Verification: {verification_status.upper()}")
    print(f"  Score:        {score} points")
    print(f"  Action:       {action_taken}")
    print()


def print_summary(repo_label, pattern_count, min_confidence, scored_results, aws_pairs):
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

    print("=" * 60)
    print("SECRET SCANNER — SCAN SUMMARY")
    print("=" * 60)
    print(f"Repository:        {repo_label}")
    print(f"Patterns loaded:    {pattern_count} ({min_confidence}-confidence)")
    print(f"Total findings:     {len(scored_results) + len(aws_pairs)} "
          f"({len(scored_results)} individual + {len(aws_pairs)} AWS credential pairs)")
    print()
    print("Severity breakdown:")
    for sev in SEVERITY_ORDER:
        label = f"{sev}:".ljust(11)
        print(f"  {colorize(label + str(severity_counts[sev]), sev)}")
    print()
    print("Verification breakdown:")
    print(f"  {'Live:'.ljust(15)}{verification_counts['live']}")
    print(f"  {'Dead:'.ljust(15)}{verification_counts['dead']}")
    print(f"  {'Unverifiable:'.ljust(15)}{verification_counts['unverifiable']}")
    print("=" * 60)
    print()


def main():
    parser = build_arg_parser()
    args = parser.parse_args()

    if args.patterns:
        patterns = load_patterns(args.patterns, min_confidence=args.min_confidence)
    else:
        patterns = load_patterns(min_confidence=args.min_confidence)

    if args.url:
        results = scan_remote_repo(args.url, patterns, scan_repo)
    else:
        results = scan_repo(args.path, patterns)

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

    # --- Output: one pass, fully resolved ---
    repo_label = args.url if args.url else args.path
    print_summary(repo_label, len(patterns), args.min_confidence, scored_results, aws_pairs)

    for severity in SEVERITY_ORDER:
        findings_in_group = [r for r in scored_results if r["severity"] == severity]
        pairs_in_group = [p for p in aws_pairs if p["severity"] == severity]

        if not findings_in_group and not pairs_in_group:
            continue

        print_section_header(severity)

        for result in findings_in_group:
            print_finding(
                result["finding"],
                result["severity"],
                result["file"],
                result["commit"],
                result["line"],
                result.get("verification_status", "unverifiable"),
                result["score"],
                result["action_taken"],
            )

        if pairs_in_group:
            print(f"--- AWS Credential Pairs ({severity}) ---")
            print()
            for pair in pairs_in_group:
                print_aws_pair(
                    pair["severity"],
                    pair["file"],
                    pair["commit"],
                    pair["access_key_id"],
                    pair["secret_key"],
                    pair["status"],
                    pair["score"],
                    pair["action_taken"],
                )

    report_path = generate_report(results, aws_pairs)
    print(f"Report written to: {report_path}")


if __name__ == "__main__":
    main()
