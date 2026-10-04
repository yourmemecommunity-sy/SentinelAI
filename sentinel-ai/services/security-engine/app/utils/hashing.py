"""Keyed digests so events can be correlated without ever storing sensitive values."""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets

# In production set SENTINEL_DIGEST_KEY (from the secret manager) so digests are stable across
# replicas. Without it a random per-process key is used: digests are still safe, just not stable.
_KEY = (os.environ.get("SENTINEL_DIGEST_KEY") or "").encode() or secrets.token_bytes(32)


def content_key() -> bytes:
    """Key for content HMACs (explanations, judge cache). Same secret as value digests, domain-separated by the caller."""
    return _KEY


def key_is_ephemeral() -> bool:
    return not os.environ.get("SENTINEL_DIGEST_KEY")


def value_digest(entity: str, value: str) -> str:
    """64-bit keyed digest prefix. Truncation limits offline brute-force value if the key leaks."""
    return hmac.new(_KEY, f"{entity}:{value}".encode(), hashlib.sha256).hexdigest()[:16]
