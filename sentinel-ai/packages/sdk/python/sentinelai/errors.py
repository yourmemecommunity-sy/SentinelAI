"""Exception hierarchy.

Every message is fixed text plus non-sensitive status data: it never contains the API key, request text or response
content, so exceptions are always safe to log.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional


class SentinelError(Exception):
    def __init__(self, message: str, status: Optional[int] = None, code: Optional[str] = None) -> None:
        super().__init__(message)
        self.status = status
        self.code = code


class SentinelConfigError(SentinelError):
    """Bad SDK configuration (missing/malformed key, insecure base URL). Raised before any network call."""


class SentinelAuthenticationError(SentinelError):
    """401: missing, malformed, unknown, revoked or expired API key."""


class SentinelPermissionError(SentinelError):
    """403 without a block decision: the key's role may not use this endpoint."""


class SentinelValidationError(SentinelError):
    """413 / 422: the request itself was rejected."""

    def __init__(self, message: str, status: int, issues: Optional[List[Dict[str, Any]]] = None) -> None:
        super().__init__(message, status, "invalid_request")
        self.issues = issues or []


class SentinelRateLimitError(SentinelError):
    def __init__(self, retry_after_seconds: Optional[float]) -> None:
        super().__init__("rate limited", 429, "rate_limited")
        self.retry_after_seconds = retry_after_seconds


class SentinelBlockedError(SentinelError):
    """The gateway BLOCKED the request (policy, injection, secrets, unknown provider, or a fail-closed condition).

    Nothing was sent to the model (input stage) or nothing was returned to you (output stage). Carries no content.
    """

    def __init__(self, stage: str, decision: str, failed_closed: bool, reason: Optional[str], event_id: Optional[str]) -> None:
        super().__init__(f"request blocked at {stage} stage ({decision}{', fail-closed' if failed_closed else ''})", 403, "blocked")
        self.stage = stage
        self.decision = decision
        self.failed_closed = failed_closed
        self.reason = reason
        self.event_id = event_id


class SentinelProviderError(SentinelError):
    """The upstream AI provider failed after the input passed security. No content is returned."""

    def __init__(self, provider_code: str, event_id: Optional[str]) -> None:
        super().__init__(f"AI provider error ({provider_code})", 502, "provider_error")
        self.provider_code = provider_code
        self.event_id = event_id


class SentinelUnavailableError(SentinelError):
    """Network failure, timeout, 5xx or an unusable response. The SDK fails closed: no content is returned."""
