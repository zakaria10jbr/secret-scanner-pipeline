# Secret Scanner Pipeline

Developers accidentally commit API keys, tokens, and passwords to Git repositories
more often than most teams would like to admit — and once a secret is in Git
history, deleting it from the latest commit doesn't remove it; it's still sitting
in an earlier commit for anyone who looks. Most secret scanners stop at telling
you *a pattern matched*. This tool goes further: it walks a repository's full Git
history and current file state to find candidate secrets, actually calls out to
the provider (AWS, GitHub, Stripe, etc.) to check whether each one is still
active, ranks every finding by real-world risk rather than treating a dead test
key the same as a live production credential, and tells you concretely what to
do about the ones that matter.

## Features

- **History + current-state detection** — the tool walks every commit's diff
  (`scan_repo`) *and* separately scans the current working tree at `HEAD`
  (`scan_current_state`). Both passes exist because they have different blind
  spots: history-walking finds secrets that were added and later deleted, but
  it can never see a repository's very first commit (no parent commit to diff
  against); the current-state pass closes that gap. Results from both passes
  are merged and deduplicated, so a secret both mechanisms catch is only
  reported once.
- **Regex + entropy detection** — regex matching against 883 curated
  high-confidence patterns (`config/rules-stable.yml`) reliably catches known
  credential formats (an AWS key always looks like `AKIA[0-9A-Z]{16}`), but is
  blind to anything it hasn't been explicitly taught to recognize. A Shannon
  entropy check (threshold 4.0) on quoted string values fills that gap by
  flagging any sufficiently random-looking value, at the cost of a higher
  false-positive rate — which is why every finding is tagged `regex` or
  `entropy` in the output, so entropy-only hits can be reviewed with
  appropriate skepticism. Obvious placeholders (`example`, `test`, `dummy`,
  `placeholder`, `your_key_here`, `xxxx`) are filtered out of both.
- **Active credential verification** — a pattern match alone doesn't tell you
  whether a secret is dangerous; a key that was rotated last year is a very
  different problem from one that still works. The tool makes a real,
  read-only API call to the issuing provider and classifies each finding as
  `live`, `dead`, or `unverifiable`. Ten provider types are covered today:
  - **AWS** — access key / secret key pairs, verified via STS `get_caller_identity`
  - **GitHub**, **GitLab** — personal access/OAuth tokens, via each platform's `/user` endpoint
  - **Slack** — via `auth.test`
  - **Stripe** — via the `/v1/balance` endpoint
  - **Dropbox** — via `get_current_account`
  - **Mailchimp** — via its datacenter-scoped `/ping` endpoint
  - **Google** — API keys, via the Discovery Service
  - **Discord** — bot tokens (`/users/@me`) and webhooks (direct request) separately

  **Shopify** is a deliberate exception: its API is scoped per-shop and
  requires a shop domain (e.g. `my-shop.myshopify.com`) that detection never
  captures, so there's no real endpoint to call. Rather than guess or fabricate
  a result, Shopify findings are always explicitly reported `unverifiable` —
  and that's documented in the code, not a silent gap. Any other finding type
  with no registered verifier (private keys, generic entropy hits, etc.) also
  reports `unverifiable`.
- **Criticality scoring** — without scoring, a live AWS key and a long-dead
  test token look identical in a flat list of matches, and a human has to
  manually figure out what actually needs attention. Each finding is scored
  by combining a secret-type weight (cloud credentials score higher than a
  Slack token), its verification result (`live` is never scored below `High`;
  `dead` is always `Low`), and a file-path penalty (a secret sitting in a
  path containing `test`, `docs`, `example`, or `spec` scores lower, since
  it's less likely to be a real production leak) — producing one of four
  severities: Critical, High, Medium, Low.
- **Remediation advice + reporting** — knowing a secret is live doesn't tell
  you what to do next. Critical/High findings are routed to
  `alert_and_advise` and attached to a provider-specific template (AWS,
  GitHub, Slack, Stripe, or a generic fallback) with concrete rotation steps
  and a link to the provider's own docs; Medium findings are
  `logged_for_digest`; Low findings are `logged_only`. Every run also writes
  a complete JSON report to `reports/findings.json` for other tooling to
  consume.
- **Baseline / incremental scanning** — a one-off manual scan benefits from
  seeing every finding every time, but a scanner wired into CI/CD (a daily
  scheduled job, or a check on every push) does not: without a way to
  remember what was already reported, every automated run re-prints the
  entire finding set from scratch, and a genuinely new secret gets buried in
  40+ already-known ones. `--baseline` fixes that by fingerprinting each
  finding (type, file, commit, and matched value — or, for AWS pairs, file,
  commit, access key, and secret key) and comparing against the previous
  run's fingerprints for that same repo. Only findings new since the last
  `--baseline` run get full detail in the output; previously-seen findings
  are still counted in the summary but not repeated in the detail tables.
  The JSON report is unaffected and always contains everything, so nothing
  is actually lost — this only trims what a human (or a CI log) has to
  re-read on every run.
- **CI/CD enforcement + GitHub Issue notification** — a scan that only
  prints to a log nobody reads doesn't actually stop a leaked secret from
  shipping. `--fail-on <severity>` makes `secretscan` exit nonzero when a
  finding at or above that severity is detected, so a CI pipeline can
  actually fail the build instead of showing a green checkmark regardless
  of what was found. `--notify-github` goes a step further and files a
  GitHub Issue per new Critical/High finding — metadata only (file,
  commit, verification status, score, remediation advice), never the
  actual secret value, since an Issue is typically far more widely visible
  than the JSON report. Both are opt-in; default behavior (exit 0, no
  issues filed) is unchanged.
- **`secretscan` CLI** — installed as a standalone command (see Installation
  below), accepting a local path or a remote Git URL, with flags to skip the
  current-state pass or load a custom pattern file (see Usage below for the
  full list).

## Installation

1. Clone the repository and enter it:
   ```bash
   git clone <this-repository-url>
   cd secret-scanner-pipeline
   ```
2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   # Windows (PowerShell):
   venv\Scripts\Activate.ps1
   # macOS/Linux:
   source venv/bin/activate
   ```
3. Install the tool as an editable package — this installs all dependencies
   and registers the `secretscan` command:
   ```bash
   pip install -e .
   ```
4. Confirm it's working:
   ```bash
   secretscan --help
   ```
   This works from any directory — `secretscan` doesn't need to be run from
   inside the project folder.

## Usage

```bash
# Scan a local repository (walks history + current working tree, the default)
secretscan --path /path/to/local/repo
```
Use this for the everyday case: you have the repository checked out locally
and want the fullest possible scan.

```bash
# Scan a remote repository over HTTPS (cloned to a temp dir, then cleaned up)
secretscan --url https://github.com/example/some-repo.git
```
Use this when you don't have (or don't want) a local clone — the tool clones
it to a temporary directory, scans, and deletes the clone automatically.

```bash
# Skip the current-state pass and only walk commit history (faster)
secretscan --path /path/to/local/repo --history-only
```
Use this for a quicker scan when you only care about what's in history and
are willing to accept the (rare) first-commit blind spot described above.

```bash
# Use a custom pattern file instead of the bundled config/rules-stable.yml
secretscan --path /path/to/local/repo --patterns config/my-custom-rules.yml
```
Use this if you maintain your own regex pattern library instead of (or in
addition to) the bundled one.

```bash
# Show real, unredacted secret values in the terminal output
secretscan --path /path/to/local/repo --show
```
Use this when you specifically need to see a real value — e.g. to confirm
which credential to rotate. By default, matched values are masked in
terminal output to prevent accidental exposure in shared screenshots,
logs, or terminal history. `--show` only affects what's printed to the
terminal — the JSON report always contains real, unredacted values
regardless of this flag (see Report Retention below).

```bash
# Write the JSON report to a specific path instead of the default,
# auto-generated, timestamped filename under reports/
secretscan --path /path/to/local/repo --output /path/to/scan-results.json
```
Use this when you need the report at a predictable, fixed location — e.g. a
CI pipeline that uploads a specific file as a build artifact. An explicit
`--output` path is never subject to the 10-file retention cleanup that
applies to the default `reports/findings_*.json` files (see Report
Retention below).

```bash
# Show only the summary block, skipping the detailed per-severity tables
secretscan --path /path/to/local/repo --summary
```
Use this for a quick headline check (totals, severity/verification
breakdown) without scrolling past full detail tables — the JSON report is
still written in full either way.

```bash
# Only show detailed findings at High severity and above
secretscan --path /path/to/local/repo --severity high
```
Use this to focus on what actually needs attention first in a large scan;
the summary block still reports the true breakdown across all severities,
and the JSON report always contains everything regardless of this flag.

```bash
# Only show detail for findings that are new since the last --baseline run
secretscan --path /path/to/local/repo --baseline
```
Use this for automated/repeated scanning — a scheduled daily scan or a
GitHub Actions check on every push — where the same 40+ already-known
findings re-printing on every single run would bury whatever's actually
new. `--baseline` fingerprints each finding and compares against the
fingerprints saved from this repo's last `--baseline` run (under
`baselines/`, keyed by a hash of the `--url`/`--path` value): only findings
new since then get full detail in the per-severity tables, while
previously-seen findings are still counted in the summary
("Baseline comparison: N new findings, M previously seen") but not
repeated in detail. At the end of the run, the current full finding set is
saved as the new baseline for next time. There's little reason to use this
for a one-off manual scan — it's meant for a scanner that runs again and
again against the same repo. The JSON report is unaffected and always
contains everything regardless of this flag.

```bash
# Exit with a nonzero status if any High-or-above finding is detected
secretscan --path /path/to/local/repo --fail-on high
```
Use this to make `secretscan` an enforcing check in CI/CD — e.g. a GitHub
Actions job that should actually fail (not just show a green checkmark)
when a serious secret is found. Exits `1` and prints a `FAIL: N finding(s)
at or above {threshold} severity detected.` line to stderr if the
threshold is met, otherwise prints a confirmation and exits `0`. Without
`--fail-on`, the tool always exits `0` regardless of findings — you have
to opt in for scan results to affect the exit code. `--fail-on` evaluates
every current finding, including ones `--baseline` would otherwise
suppress from the detail tables: a Critical secret still fails the build
whether or not it's new since the last run.

```bash
# File a GitHub Issue for each new Critical/High finding
export GITHUB_TOKEN=ghp_your_personal_access_token
secretscan --path /path/to/local/repo --baseline --notify-github
```
Use this so a serious secret actually notifies someone instead of only
existing in a JSON report nobody's watching. The token is read from the
`GITHUB_TOKEN` environment variable only — never pass it as a CLI flag,
since flag values can leak into shell history or process listings (`ps`,
task managers, CI job logs that echo the invoking command). The target
repo defaults to the scanned repo's own `origin` remote if it's hosted on
GitHub (detected automatically); pass `--github-repo owner/repo`
explicitly if that detection fails (non-GitHub remotes, `--url` scans
against a mirror, etc.). Filed issues are metadata-only — file, commit,
verification status, score, and remediation advice — and never contain
the actual matched secret value. **Use `--notify-github` together with
`--baseline`**: without it, every qualifying finding is notified on
*every* run, since there's no prior-scan state to tell "new" from
"already known," which means duplicate issues on repeated/scheduled
scans. If issue creation fails for any reason (bad token, rate limit,
network error), that finding's failure is printed and the scan continues
normally — it never crashes the run.

The token can be a [Personal Access Token](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens)
(classic or fine-grained, with `issues:write` on the target repo) for
running `secretscan` locally or from a script, or — inside a GitHub
Actions job — the workflow's automatic `${{ secrets.GITHUB_TOKEN }}`,
exported as an environment variable to the step (`env: GITHUB_TOKEN:
${{ secrets.GITHUB_TOKEN }}`), provided the job's permissions grant it
`issues: write`. Either way, never hardcode a token in the workflow file
or pass it as a command-line argument.

```bash
# Flags can be combined
secretscan --url https://github.com/example/some-repo.git --history-only --severity high --output results.json
secretscan --path /path/to/local/repo --baseline --severity high
secretscan --path /path/to/local/repo --baseline --fail-on critical
secretscan --path /path/to/local/repo --baseline --notify-github --fail-on high
```

`--path` and `--url` are mutually exclusive and one is required. Run
`secretscan --help` for the full flag reference.

## Example Output

```
┌──────────────────────────────────────────────────────────┐
│                     SECRET SCANNER                        │
│           detect -> verify -> score -> remediate          │
└──────────────────────────────────────────────────────────┘

Scanning commit history  ████████████████████████ 100%  28/28

                    SECRET SCANNER — SCAN SUMMARY
┌─────────────────────────┬──────────────────────────────────────────┐
│ Repository              │ /path/to/local/repo                       │
│ Patterns loaded         │ 883 (high-confidence)                     │
│ Scan mode               │ History + current-state (default)         │
│ Total findings          │ 43 (24 individual + 19 AWS credential...) │
│ Detection method        │ Regex-matched: 9   Entropy-only: 15       │
│ Severity breakdown      │ Critical: 0  High: 12  Medium: 17  Low:14 │
│ Verification breakdown  │ Live: 0   Dead: 14   Unverifiable: 29     │
└─────────────────────────┴──────────────────────────────────────────┘

────────────────────────────── HIGH ───────────────────────────────────
┌────────────────────────┬──────────────────────┬───────────────┬───────┬───────────────────┬─────────┐
│ Finding Type            │ File                 │ Verif.        │ Score │ Action             │ Present │
├────────────────────────┼──────────────────────┼───────────────┼───────┼───────────────────┼─────────┤
│ Password in URL         │ my_config.py (d431b0)│ UNVERIFIABLE  │  45   │ alert_and_advise   │   Yes   │
│ Asymmetric Private Key  │ BARE-SECRETS (1fd84a)│ UNVERIFIABLE  │  50   │ alert_and_advise   │   Yes   │
└────────────────────────┴──────────────────────┴───────────────┴───────┴───────────────────┴─────────┘

Report written to: reports/findings.json
```

(The real output additionally shows a `Value` column with the matched
string, and colors severities red/orange/yellow/green in the terminal;
condensed here for readability.)

## Project Structure

```
secret-scanner-pipeline/
├── config/
│   └── rules-stable.yml       # regex pattern library (883 high-confidence patterns)
├── scanner/                   # core package
│   ├── detectors.py           #   pattern loading, regex/entropy detection, git history + current-state walking
│   ├── verifier.py            #   live credential verification against provider APIs
│   ├── scoring.py             #   criticality scoring and severity thresholds
│   ├── remediation.py         #   remediation templates, severity routing, JSON report generation
│   ├── remote.py              #   clone-scan-cleanup flow for --url targets
│   ├── baseline.py            #   finding fingerprinting and baseline diff/save for --baseline
│   └── notify.py              #   GitHub Issue creation for --notify-github, GitHub repo detection
├── scripts/
│   └── check_github_coverage.py  # dev utility: audits pattern coverage against GitHub's recognized providers
├── tests/                     # pytest suite
│   ├── test_scoring.py
│   ├── test_remediation.py
│   ├── test_baseline.py
│   └── test_notify.py
├── reports/                   # timestamped JSON scan reports (gitignored; see Report Retention below)
├── baselines/                 # per-repo finding-ID snapshots for --baseline (gitignored)
├── main.py                    # CLI entry point (argparse) and scan orchestration
├── pyproject.toml             # packaging config and the `secretscan` console-script entry point
├── requirements.txt           # dependency list
└── .gitignore
```

## Report Retention

Every scan writes a new, timestamped report to
`reports/findings_YYYY-MM-DD_HHMMSS.json` rather than overwriting a single
fixed file. **These reports contain real, unredacted secret values by
default** — regardless of whether `--show` was passed for the terminal
output, since redaction only ever applies to what's printed, not to the
report file (see Usage above). To keep that exposure bounded, only the 10
most recent report files are kept; after each scan, older ones are deleted
automatically (`cleanup_old_reports()` in `scanner/remediation.py`).

`reports/` is gitignored, so these files are never committed by default, but
still treat the folder as sensitive: don't disable the gitignore rule for it,
and if you copy a report elsewhere (e.g. attaching it to a ticket), redact or
delete it afterward rather than leaving it lying around.

## Testing

```bash
python -m pytest tests/ -v
```

84 tests currently pass, covering the scoring engine (`test_scoring.py` —
type/verification weight combinations, severity thresholds, the file-path
penalty and its zero-floor), the remediation stage (`test_remediation.py`
— severity-to-action routing, template category matching, JSON report
structure, the default timestamped filename, and report retention/cleanup),
the CLI's severity-filtering and `--fail-on` logic (`test_main.py`),
baseline diffing (`test_baseline.py` — finding-ID stability/uniqueness
across type, file, commit, and value, the separate AWS-pair hashing, and
new-vs-previously-seen diffing), deterministic AWS candidate pairing
(`test_verifier.py`), current-state directory exclusion (`test_detectors.py`
— `.git`/`__pycache__`/`.pytest_cache`/`*.egg-info`/`node_modules` pruning),
and GitHub Issue notification (`test_notify.py` — issue title/body
construction, confirming the matched secret value is never included in an
issue body, GitHub-slug URL parsing, and graceful failure handling on auth
errors, rate limits, and network errors, all network-mocked). These tests
exercise scoring, remediation, CLI, baseline, verifier, detector, and
notification logic directly; detection and live-verification behavior
against real provider APIs are validated by running the tool against real
repositories rather than by unit test.

## Known Limitations

- **Partial verification coverage** — active verification covers 10 provider
  types (27 of the 31 pattern names with a registered verifier; the other 4
  are Shopify's always-`unverifiable` case) out of the 883 detectable
  high-confidence patterns; everything else — private keys, generic entropy
  findings, and dozens of other provider-specific patterns — always reports
  `unverifiable`.
- **Proximity-based AWS pairing** — an AWS access key is paired with whichever
  candidate secret key shares its commit and file, which is a heuristic, not
  a guaranteed-correct match in files with multiple credentials.
- **Exact-value-only deduplication** — a finding is only deduplicated against
  another if their matched string is identical; a secret that changed even
  slightly between its historical and current form is reported twice.

## Credits

- Regex pattern library adapted from
  [mazen160/secrets-patterns-db](https://github.com/mazen160/secrets-patterns-db).
- Test fixtures used during development:
  [zakaria10jbr/secret-scanner-test-fixtures](https://github.com/zakaria10jbr/secret-scanner-test-fixtures).
