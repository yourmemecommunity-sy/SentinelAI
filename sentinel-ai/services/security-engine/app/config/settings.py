"""Environment-driven settings. Security-relevant limits have safe defaults."""
from __future__ import annotations

import os
from dataclasses import dataclass

DETECTOR_BUNDLE_VERSION = "2026.09.1-ner"


@dataclass(frozen=True)
class Settings:
    environment: str = "development"
    max_input_chars: int = 500_000
    time_budget_ms: int = 1500
    # NER costs ~18 ms per 1,000 characters (en_core_web_md, measured) and can run twice per scan (detection + the
    # post-sanitization verification pass), so the budget grows with the input instead of failing every large document
    # closed. The gateway's timeout grows the same way with a larger allowance (SECURITY_TIMEOUT_PER_KCHAR_MS).
    time_budget_per_kchar_ms: int = 45
    ner_enabled: bool = True
    ner_model: str = "en_core_web_md"
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
            time_budget_per_kchar_ms=int(os.environ.get("SECURITY_TIME_BUDGET_PER_KCHAR_MS", "45")),
            ner_enabled=os.environ.get("SENTINEL_NER", "on").strip().lower() not in ("off", "false", "0", "no"),
            ner_model=os.environ.get("SENTINEL_NER_MODEL", "en_core_web_md"),
            internal_token=os.environ.get("SECURITY_ENGINE_TOKEN") or None,
            vault_url=os.environ.get("VAULT_URL") or None,
            vault_token=os.environ.get("VAULT_TOKEN") or None,
            vault_timeout_s=float(os.environ.get("VAULT_TIMEOUT_S", "0.5")),
        )
        # Fail closed on misconfiguration: never run an unauthenticated engine in production.
        if s.environment == "production" and not s.internal_token:
            raise RuntimeError("SECURITY_ENGINE_TOKEN must be set when SENTINEL_ENV=production")
        # Names and locations are only detected by the NER layer: production must not silently run without it.
        if s.environment == "production" and not s.ner_enabled:
            raise RuntimeError("SENTINEL_NER=off is not allowed when SENTINEL_ENV=production")
        if s.environment == "production" and s.vault_url and not s.vault_token:
            raise RuntimeError("VAULT_TOKEN must be set when VAULT_URL is set in production")
        return s
