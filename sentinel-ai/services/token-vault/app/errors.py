"""Vault error taxonomy. None of these messages ever contain a value, a token's plaintext, or a key."""
from __future__ import annotations


class VaultError(Exception):
    """Base class."""


class VaultUnavailable(VaultError):
    """Redis could not be reached, timed out, or the circuit breaker is open. Callers must fail closed (or, for hydration,
    leave tokens un-hydrated, which is the safe direction)."""


class VaultLimitExceeded(VaultError):
    """The session holds the maximum number of tokens, or a batch/value is over its cap."""


class TokenizationRefused(VaultError):
    """The entity type may never be tokenized (credentials, secrets, cards, threats), or the input is malformed."""
