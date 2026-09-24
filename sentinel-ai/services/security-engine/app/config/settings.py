"""Environment-driven settings. Security-relevant limits have safe defaults."""
from __future__ import annotations

import os
from dataclasses import dataclass

DETECTOR_BUNDLE_VERSION = "2026.09.0-phase1"


@dataclass(frozen=True)
class Settings:
    environment: str = "development"
    max_input_chars: int = 500_000
    time_budget_ms: int = 1500
    internal_token: str | None = None
    vault_url: str | None = None          # token-vault base URL; without it a session-scoped TOKENIZE degrades to REDACT
    vault_token: str | None = None
    vault_timeout_s: float = 0.5

    @classmethod
    def from_env(cls) -> "Settings":
        s = cls(
            environment=os.environ.get("SENTINEL_ENV", "development"),
            max_input_chars=int(os.environ.get("SECURITY_MAX_INPUT_CHARS", "500000")),
            time_budget_ms=int(os.environ.get("SECURITY_TIME_BUDGET_MS", "1500")),
            internal_token=os.environ.get("SECURITY_ENGINE_TOKEN") or None,
            vault_url=os.environ.get("VAULT_URL") or None,
            vault_token=os.environ.get("VAULT_TOKEN") or None,
            vault_timeout_s=float(os.environ.get("VAULT_TIMEOUT_S", "0.5")),
        )
        # Fail closed on misconfiguration: never run an unauthenticated engine in production.
        if s.environment == "production" and not s.internal_token:
            raise RuntimeError("SECURITY_ENGINE_TOKEN must be set when SENTINEL_ENV=production")
        if s.environment == "production" and s.vault_url and not s.vault_token:
            raise RuntimeError("VAULT_TOKEN must be set when VAULT_URL is set in production")
        return s
