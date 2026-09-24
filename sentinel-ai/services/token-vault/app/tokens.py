"""Token wire format, the tokenizable-entity allow-list, and value normalization.

Format: ``[TOK_<TYPE>_<n>]`` e.g. ``[TOK_NAME_1]``. TYPE is upper-case letters and underscores (never digits, so the trailing
``_<n>`` is unambiguous); n is a per-session, per-type counter. The format is deliberately regular so a streaming parser can
decide, from at most MAX_TOKEN_LEN-1 buffered characters, whether a trailing ``[`` can still become a token.
"""
from __future__ import annotations

import re
import unicodedata

from app.errors import TokenizationRefused

TYPE_PATTERN = r"[A-Z](?:[A-Z_]{0,30}[A-Z])?"
TOKEN_RE = re.compile(rf"\[TOK_({TYPE_PATTERN})_([0-9]{{1,6}})\]")
_TOKEN_FULL = re.compile(rf"\[TOK_({TYPE_PATTERN})_([0-9]{{1,6}})\]")
# "[TOK_" (5) + type (<=32) + "_" (1) + digits (<=6) + "]" (1)
MAX_TOKEN_LEN = 45
# A string that is a strict prefix of some possible token. Permissive on purpose: over-holding a few characters is harmless,
# under-holding would let a token be split across output chunks and leak un-hydrated.
_PREFIX = re.compile(r"\[(?:T|TO|TOK|TOK_[A-Z0-9_]{0,39})?")

# Default-deny. Only these types can ever enter the vault. Credentials, secrets, cards and threat entities are absent by design
# (a cross-check test asserts none of the engine's CRITICAL/credential entity types is listed here).
TOKENIZABLE: frozenset[str] = frozenset({
    "NAME", "EMAIL", "PHONE", "ADDRESS", "DATE_OF_BIRTH", "PAN", "AADHAAR", "PASSPORT", "SSN", "DRIVER_LICENSE",
    "BANK_ACCOUNT", "UPI", "IFSC", "INTERNAL_URL", "CUSTOM_CONFIDENTIAL", "ORGANIZATION", "LOCATION",
})
_ALNUM_ONLY = frozenset({"PHONE", "AADHAAR", "SSN", "BANK_ACCOUNT", "PAN", "PASSPORT", "DRIVER_LICENSE", "IFSC"})
_CASEFOLD = frozenset({"EMAIL", "NAME", "INTERNAL_URL", "ORGANIZATION", "LOCATION", "ADDRESS", "UPI"})
_NON_ALNUM = re.compile(r"[^0-9A-Za-z]")


def make_token(entity: str, n: int) -> str:
    if not re.fullmatch(TYPE_PATTERN, entity) or not 1 <= n <= 999_999:
        raise TokenizationRefused("invalid token parameters")
    return f"[TOK_{entity}_{n}]"


def is_token(s: str) -> bool:
    return len(s) <= MAX_TOKEN_LEN and _TOKEN_FULL.fullmatch(s) is not None


def is_token_prefix(tail: str) -> bool:
    """True if `tail` (which starts with '[') could still grow into a token."""
    return len(tail) < MAX_TOKEN_LEN and _PREFIX.fullmatch(tail) is not None


def token_entity(token: str) -> str:
    m = _TOKEN_FULL.fullmatch(token)
    if not m:
        raise TokenizationRefused("not a token")
    return m.group(1)


def require_tokenizable(entity: str) -> None:
    if entity not in TOKENIZABLE:
        raise TokenizationRefused("entity type cannot be tokenized")


def normalize(entity: str, value: str) -> str:
    """Canonical form used ONLY to decide 'same value' (the first-seen spelling is what gets restored)."""
    v = " ".join(unicodedata.normalize("NFKC", value).split())
    if entity in _ALNUM_ONLY:
        v = _NON_ALNUM.sub("", v).upper()
    elif entity in _CASEFOLD:
        v = v.casefold()
    return v
