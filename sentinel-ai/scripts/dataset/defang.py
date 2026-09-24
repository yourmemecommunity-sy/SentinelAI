"""At-rest format of secret-shaped values in the evaluation datasets.

The SECRETS and OUTPUT_LEAKAGE records exist to grade the engine on realistic credentials (AWS keys, Stripe/Slack/GitHub/
Google tokens, JWTs, PEM private keys, passwords, connection strings). Stored verbatim, those synthetic values are
indistinguishable from real ones to secret scanners (GitHub push protection blocks them, as it should), and anyone
copying a record could not tell them apart either.

So they are stored DEFANGED: every secret-type entity value is split into 8-character chunks joined by the inert marker
`[FAKE]`. No credential pattern matches across the marker (they all need 16+ contiguous token characters), and the stored
text visibly announces that it is not a credential. Loading materializes the realistic value in memory by removing the
marker, so the engine is evaluated on exactly the same strings as before and every entity offset (which refers to the
materialized text) is unchanged.

Every value is still produced by the seeded generator (`generate_synthetic_datasets.py`, seed 20260919): none is, or was
ever, a real credential.
"""
from __future__ import annotations

import re

MARK = "[FAKE]"
CHUNK = 8

# Entity types whose values must never be stored contiguously.
SECRET_ENTITY_TYPES = frozenset({
    "API_KEY", "AWS_CREDENTIAL", "GITHUB_TOKEN", "GOOGLE_CREDENTIAL", "JWT", "OAUTH_TOKEN", "PASSWORD",
    "PRIVATE_KEY", "CONNECTION_STRING", "HIGH_ENTROPY_SECRET",
})

# Patterns that must never appear in a stored dataset file. The evaluator refuses to run if one does, so a regeneration
# that forgot to defang cannot slip through. (Assembled so this file does not match them itself.)
RAW_SECRET_PATTERNS = [
    ("AWS access key id", re.compile(r"\b(?:AK" r"IA|AS" r"IA)[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh" r"[pousr]_[A-Za-z0-9]{36,}\b")),
    ("Google API key", re.compile(r"\bAI" r"za[0-9A-Za-z_-]{35}\b")),
    ("Stripe secret key", re.compile(r"\b[rs]k_(?:li" r"ve|te" r"st)_[0-9A-Za-z]{16,}")),
    ("Slack token", re.compile(r"\bxo" r"x[abprs]-[0-9A-Za-z-]{10,}")),
    ("OpenAI-style key", re.compile(r"\bsk" r"-[A-Za-z0-9]{32,}\b")),
    ("private key block", re.compile(r"-----BEGIN [A-Z ]*PRIV" r"ATE KEY-----")),
    ("JWT", re.compile(r"\bey" r"J[A-Za-z0-9_-]{10,}\.ey" r"J[A-Za-z0-9_-]{10,}\.")),
    ("URL with embedded password", re.compile(r"[a-z+]+://[A-Za-z0-9._~%-]+:[A-Za-z0-9._~%!$&'()*+,;=-]{6,}@")),
]


def defang(value: str) -> str:
    """Store form of a secret-type value: 8-character chunks joined by MARK."""
    return MARK.join(value[i:i + CHUNK] for i in range(0, len(value), CHUNK))


def materialize(text: str) -> str:
    """The realistic text the engine is evaluated on (inverse of defang)."""
    return text.replace(MARK, "")


def raw_secret_findings(stored_text: str) -> list[str]:
    """Names of the credential patterns found in a STORED text (must be empty)."""
    return [name for name, rx in RAW_SECRET_PATTERNS if rx.search(stored_text)]
