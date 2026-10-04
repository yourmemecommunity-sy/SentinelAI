"""Environment-driven settings. Security-relevant limits have safe defaults."""
from __future__ import annotations

import os
from dataclasses import dataclass

DETECTOR_BUNDLE_VERSION = "2026.10.1-cascade"


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
    # Detection cascade (tier 2 classifier, tier 3 judge). Off in the dataclass default so unit tests never need the
    # model files; on by default from the environment (Settings.from_env). Thresholds: chosen on TRAINING splits only,
    # see docs/verification/12-ai-vs-ai.md.
    cascade_enabled: bool = False
    classifier_dir: str = "/srv/models/injection-classifier"
    # protectai/deberta-v3-base-prompt-injection-v2; thresholds from TRAIN data only (scripts/security/choose_thresholds.py
    # --benign-extra, D43): each limit holds on every benign train source (deepset prompts AND ai4privacy business text):
    # threshold = FP <= 2%; band_high = FP <= 0.5% (here: never, below 1.0); band_low = judge call rate <= 20%.
    classifier_threshold: float = 0.99999
    judge_band_low: float = 0.99008
    judge_band_high: float = 1.0
    # Classifier cost bound (measured on jackhhao TRAIN prompts, 2 threads: ~1.5 s per 512-token window at p95).
    classifier_threads: int = 2
    classifier_max_windows: int = 4
    classifier_budget_per_window_ms: int = 1600
    anthropic_api_key: str | None = None
    judge_enabled: bool = True             # only effective with an API key
    judge_model: str = "claude-haiku-4-5"
    judge_timeout_s: float = 4.0

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
            # Default: on in production (where it is mandatory, like NER), off in development unless SENTINEL_CASCADE=on.
            cascade_enabled=os.environ.get(
                "SENTINEL_CASCADE", "on" if os.environ.get("SENTINEL_ENV", "development") == "production" else "off",
            ).strip().lower() not in ("off", "false", "0", "no"),
            classifier_dir=os.environ.get("SENTINEL_CLASSIFIER_DIR", "/srv/models/injection-classifier"),
            classifier_threshold=float(os.environ.get("SENTINEL_CLASSIFIER_THRESHOLD", str(cls.classifier_threshold))),
            judge_band_low=float(os.environ.get("SENTINEL_JUDGE_BAND_LOW", str(cls.judge_band_low))),
            judge_band_high=float(os.environ.get("SENTINEL_JUDGE_BAND_HIGH", str(cls.judge_band_high))),
            classifier_threads=int(os.environ.get("SENTINEL_CLASSIFIER_THREADS", "2")),
            classifier_max_windows=int(os.environ.get("SENTINEL_CLASSIFIER_MAX_WINDOWS", "4")),
            classifier_budget_per_window_ms=int(os.environ.get("SENTINEL_CLASSIFIER_MS_PER_WINDOW", "1600")),
            anthropic_api_key=os.environ.get("ANTHROPIC_API_KEY") or None,
            judge_enabled=os.environ.get("SENTINEL_JUDGE", "on").strip().lower() not in ("off", "false", "0", "no"),
            judge_model=os.environ.get("SENTINEL_JUDGE_MODEL", "claude-haiku-4-5"),
            judge_timeout_s=float(os.environ.get("SENTINEL_JUDGE_TIMEOUT_S", "4")),
        )
        # Fail closed on misconfiguration: never run an unauthenticated engine in production.
        if s.environment == "production" and not s.internal_token:
            raise RuntimeError("SECURITY_ENGINE_TOKEN must be set when SENTINEL_ENV=production")
        # Names and locations are only detected by the NER layer: production must not silently run without it.
        if s.environment == "production" and not s.ner_enabled:
            raise RuntimeError("SENTINEL_NER=off is not allowed when SENTINEL_ENV=production")
        # Prompt-injection detection relies on the cascade's classifier: production must not silently run without it.
        if s.environment == "production" and not s.cascade_enabled:
            raise RuntimeError("SENTINEL_CASCADE=off is not allowed when SENTINEL_ENV=production")
        # Content HMACs (replay) and value digests must be stable across workers and restarts in production.
        if s.environment == "production" and not os.environ.get("SENTINEL_DIGEST_KEY"):
            raise RuntimeError("SENTINEL_DIGEST_KEY must be set when SENTINEL_ENV=production")
        if s.environment == "production" and s.vault_url and not s.vault_token:
            raise RuntimeError("VAULT_TOKEN must be set when VAULT_URL is set in production")
        return s
