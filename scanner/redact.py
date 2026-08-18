# scanner/redact.py
#
# Secret redaction for display/output only. Never use this on a value before
# verification (verify_secret, pair_and_verify_aws) — it needs the real value
# to work correctly. Redaction happens only at the final print/write step.


def redact_value(value):
    """Mask a secret value for safe display: keep the first and last 4
    characters, replace everything in between with asterisks. Values of 8
    characters or fewer are masked entirely, since there isn't enough length
    to hide anything meaningful by only trimming the ends."""
    if not isinstance(value, str):
        return "****"
    if not value:
        return ""
    if len(value) <= 8:
        return "*" * len(value)
    return value[:4] + ("*" * (len(value) - 8)) + value[-4:]
