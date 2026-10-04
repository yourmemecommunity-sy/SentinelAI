"""Cascade configuration: mandatory in production (like NER), opt-in in development; stable digest key in production."""
import pytest

from app.config.settings import Settings

PROD = {"SENTINEL_ENV": "production", "SECURITY_ENGINE_TOKEN": "e" * 20, "SENTINEL_DIGEST_KEY": "d" * 32}


def env(monkeypatch, **values):
    for k in ("SENTINEL_ENV", "SECURITY_ENGINE_TOKEN", "SENTINEL_DIGEST_KEY", "SENTINEL_CASCADE", "VAULT_URL", "SENTINEL_NER"):
        monkeypatch.delenv(k, raising=False)
    for k, v in values.items():
        monkeypatch.setenv(k, v)


def test_cascade_is_on_in_production_and_cannot_be_switched_off(monkeypatch):
    env(monkeypatch, **PROD)
    assert Settings.from_env().cascade_enabled
    env(monkeypatch, **PROD, SENTINEL_CASCADE="off")
    with pytest.raises(RuntimeError, match="SENTINEL_CASCADE"):
        Settings.from_env()


def test_cascade_is_opt_in_in_development(monkeypatch):
    env(monkeypatch)
    assert not Settings.from_env().cascade_enabled
    env(monkeypatch, SENTINEL_CASCADE="on")
    assert Settings.from_env().cascade_enabled


def test_production_requires_a_stable_digest_key(monkeypatch):
    env(monkeypatch, **{k: v for k, v in PROD.items() if k != "SENTINEL_DIGEST_KEY"})
    with pytest.raises(RuntimeError, match="SENTINEL_DIGEST_KEY"):
        Settings.from_env()


def test_the_judge_is_only_configured_with_a_key(monkeypatch):
    from app.cascade.factory import build_judge
    env(monkeypatch)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert build_judge(Settings.from_env()) is None
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-not-a-real-key")
    monkeypatch.setenv("SENTINEL_JUDGE", "off")
    assert build_judge(Settings.from_env()) is None
