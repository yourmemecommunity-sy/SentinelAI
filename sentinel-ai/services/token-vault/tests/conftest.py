from __future__ import annotations

import asyncio
import os
import time
from collections.abc import Callable

import pytest
from fakeredis import FakeServer

from app.backend import CircuitBreaker, RedisBackend
from app.config.settings import Settings
from app.crypto import KeyRing
from app.factory import build_fake_client
from app.vault import SessionRef, Vault

# Fixed, non-secret test key material (a real deployment configures VAULT_MASTER_KEYS).
KEY1 = bytes(range(32))
KEY2 = bytes(range(100, 132))


class Clock:
    """Controllable wall clock. Starts at the real time because fakeredis evaluates EXPIREAT against the real clock."""

    def __init__(self) -> None:
        self.t = time.time()

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


@pytest.fixture
def clock() -> Clock:
    return Clock()


def _settings_for_tests() -> Settings:
    return Settings(backend="memory", ttl_seconds=3600, op_timeout_s=0.5, retries=1, breaker_threshold=3, breaker_cooldown_s=0.2)


@pytest.fixture
def settings() -> Settings:
    return _settings_for_tests()


@pytest.fixture
def keyring() -> KeyRing:
    return KeyRing({"k1": KEY1}, "k1")


# Set VAULT_TEST_REDIS_URL to run the whole suite against a REAL Redis server (see scripts/development/wsl-infra.sh).
# Without it the suite uses fakeredis, which is fast but is not a real server.
REAL_REDIS_URL = os.environ.get("VAULT_TEST_REDIS_URL")
USING_REAL_REDIS = bool(REAL_REDIS_URL)


@pytest.fixture
async def redis():
    if REAL_REDIS_URL:
        import dataclasses as _dc

        from app.factory import build_client

        # Build it exactly as production does (bounded blocking pool), so the real-Redis run exercises the real client.
        # Use the suite's Settings so the socket timeout matches the backend's per-operation timeout; mismatched budgets
        # made heavy-concurrency tests marginal against a server one network hop away.
        r = build_client(_dc.replace(_settings_for_tests(), backend="redis", redis_url=REAL_REDIS_URL))
        await r.flushdb()               # each test starts from a clean database
        yield r
        await r.flushdb()
        await r.aclose()
        return
    # Same bounded, blocking pool as production (see app.factory.build_fake_client).
    r = build_fake_client(_settings_for_tests(), FakeServer())
    yield r
    await r.aclose()


@pytest.fixture
def make_vault(redis, keyring, settings, clock) -> Callable[..., Vault]:
    def make(*, client=None, ring: KeyRing | None = None, s: Settings | None = None) -> Vault:
        st = s or settings
        backend = RedisBackend(client or redis, op_timeout_s=st.op_timeout_s, retries=st.retries,
                               breaker=CircuitBreaker(st.breaker_threshold, st.breaker_cooldown_s), clock=clock)
        return Vault(backend, ring or keyring, st)

    return make


@pytest.fixture
def vault(make_vault) -> Vault:
    return make_vault()


@pytest.fixture
def ref() -> SessionRef:
    return SessionRef("org-1", "session-1")


@pytest.fixture
def racing_vault(make_vault) -> Vault:
    """A vault whose every Redis operation first yields to the event loop. fakeredis never suspends on its own, so without this
    concurrent tasks run one after another and the race handling (lost HSETNX, orphan cleanup) would never execute."""
    v = make_vault()
    real = v._b._run

    async def yielding(op):
        await asyncio.sleep(0)
        return await real(op)

    v._b._run = yielding
    return v
