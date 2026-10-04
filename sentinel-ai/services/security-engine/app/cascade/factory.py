"""Builds the cascade from settings. A configured but broken classifier is kept (unhealthy) so /ready reports it and
every scan fails closed; it is never silently dropped."""
from __future__ import annotations

from pathlib import Path

from app.cascade.budget import BudgetLedger
from app.cascade.cascade import Cascade, CascadeConfig
from app.cascade.classifier import OnnxInjectionClassifier
from app.cascade.judge import AnthropicJudge, CachedJudge, Judge
from app.config.settings import Settings
from app.utils.hashing import content_key


def build_judge(settings: Settings, ledger: BudgetLedger | None = None) -> Judge | None:
    """The Claude judge, or None when it is not configured (no API key, or SENTINEL_JUDGE=off)."""
    if not settings.judge_enabled or not settings.anthropic_api_key:
        return None
    inner = AnthropicJudge(settings.anthropic_api_key, ledger or BudgetLedger.from_env(), model=settings.judge_model,
                           timeout_s=settings.judge_timeout_s)
    return CachedJudge(inner, content_key())


def build_cascade(settings: Settings) -> Cascade | None:
    if not settings.cascade_enabled:
        return None
    classifier = OnnxInjectionClassifier(Path(settings.classifier_dir), threads=settings.classifier_threads,
                                         max_windows=settings.classifier_max_windows)
    config = CascadeConfig(threshold=settings.classifier_threshold, band_low=settings.judge_band_low,
                           band_high=settings.judge_band_high)
    return Cascade(classifier, build_judge(settings), config)
