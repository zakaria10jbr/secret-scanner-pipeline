# check_github_coverage.py
#
# Compares our pattern library (config/rules-stable.yml) against GitHub's
# officially-recognized secret scanning partner providers, to surface
# provider categories we have no high-confidence pattern for.

import yaml

PATTERNS_PATH = "config/rules-stable.yml"

GITHUB_PROVIDERS = [
    "adafruit", "alibaba", "aws", "atlassian", "azure", "clojars",
    "databricks", "discord", "dropbox", "dynatrace", "finicity",
    "frameio", "github", "gocardless", "google", "terraform",
    "hashicorp", "vault", "hubspot", "mailchimp", "mailgun", "npm",
    "nuget", "palantir", "postman", "proctorio", "pulumi", "samsara",
    "shopify", "slack", "sslmate", "stripe", "tencent", "twilio",
]


def load_high_confidence_pattern_names(filepath=PATTERNS_PATH):
    with open(filepath, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    names = []
    for entry in data["patterns"]:
        p = entry["pattern"]
        if p.get("confidence") == "high":
            names.append(p["name"])

    return names


def main():
    pattern_names = load_high_confidence_pattern_names()

    covered_count = 0
    rows = []

    for provider in GITHUB_PROVIDERS:
        matches = [name for name in pattern_names if provider in name.lower()]
        covered = len(matches) > 0
        if covered:
            covered_count += 1

        examples = matches[:3]
        if len(matches) > 3:
            examples_display = ", ".join(examples) + f" +{len(matches) - 3} more"
        else:
            examples_display = ", ".join(examples)

        rows.append((provider, "YES" if covered else "no", examples_display))

    provider_width = max(len(r[0]) for r in rows) + 2
    status_width = max(len("Covered"), len("YES")) + 2

    header = f"{'Provider':<{provider_width}}{'Covered':<{status_width}}Example matching patterns"
    print(header)
    print("-" * len(header))
    for provider, status, examples_display in rows:
        print(f"{provider:<{provider_width}}{status:<{status_width}}{examples_display}")

    print()
    print(f"Total high-confidence patterns loaded: {len(pattern_names)}")
    print(f"Coverage: {covered_count} / {len(GITHUB_PROVIDERS)} GitHub-recognized provider categories represented")


if __name__ == "__main__":
    main()
