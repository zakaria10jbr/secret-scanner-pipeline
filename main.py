import argparse
import sys

from scanner.detectors import load_patterns, scan_repo
from scanner.verifier import verify_secret, pair_and_verify_aws
from scanner.remote import scan_remote_repo
from scanner.scoring import score_finding


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


def main():
    parser = build_arg_parser()
    args = parser.parse_args()

    if args.patterns:
        patterns = load_patterns(args.patterns, min_confidence=args.min_confidence)
    else:
        patterns = load_patterns(min_confidence=args.min_confidence)

    print(f"Loaded {len(patterns)} {args.min_confidence}-confidence patterns\n")

    if args.url:
        results = scan_remote_repo(args.url, patterns, scan_repo)
    else:
        results = scan_repo(args.path, patterns)

    print(f"\nRunning verification on findings...\n")
    for result in results:
        secret_type = result["finding"]
        if secret_type in ("AWS API Key", "AWS Access Key ID Value"):
            continue
        value = result["line"]
        status = verify_secret(secret_type, value)
        result["verification_status"] = status
        print(f"[{status.upper()}] {secret_type} — {result['file']}: {value}")

    print(f"\nRunning AWS credential pairing and verification...\n")
    aws_pairs = pair_and_verify_aws(results)
    for pair in aws_pairs:
        print(f"[{pair['status'].upper()}] AWS pair — {pair['file']} @ {pair['commit']}: "
              f"{pair['access_key_id']} / {pair['secret_key']}")

    print(f"\nScoring findings...\n")
    for result in results:
        if result["finding"] in ("AWS API Key", "AWS Access Key ID Value"):
            continue  # already scored separately via AWS pairing
        status = result.get("verification_status", "unverifiable")
        scored = score_finding(result["finding"], status)
        result["score"] = scored["score"]
        result["severity"] = scored["severity"]
        print(f"[{scored['severity'].upper()}] ({scored['score']}) {result['finding']} — {result['file']}: {result['line']}")

    print(f"\nScoring AWS pairs...\n")
    for pair in aws_pairs:
        scored = score_finding("AWS pair", pair["status"])
        pair["score"] = scored["score"]
        pair["severity"] = scored["severity"]
        print(f"[{scored['severity'].upper()}] ({scored['score']}) AWS pair — {pair['file']} @ {pair['commit']}")

    print(f"\nTotal findings: {len(results)}")


if __name__ == "__main__":
    main()