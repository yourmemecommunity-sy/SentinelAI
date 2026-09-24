import asyncio
import time

import pytest
from redis import exceptions as rexc

from app.backend import CircuitBreaker, RedisBackend
from app.errors import VaultUnavailable
from app.vault import SessionRef, Vault
from app.detokenize import StreamState, detokenize_json, detokenize_stream


class _Pipe:
    def __init__(self, owner):
        self.o = owner

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    def __getattr__(self, name):
        return lambda *a, **k: None          # queued commands are no-ops

    async def execute(self):
        return await self.o._act()


class BrokenRedis:
    """Stands in for a redis client whose every call fails (or hangs) in a chosen way."""

    def __init__(self, exc=None, delay=0.0):
        self.exc, self.delay, self.calls = exc, delay, 0

    async def _act(self):
        self.calls += 1
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.exc:
            raise self.exc
        return [None]

    def pipeline(self, transaction=False):
        return _Pipe(self)

    def __getattr__(self, name):
        async def call(*a, **k):
            return await self._act()

        return call


def vault_on(client, settings, keyring, clock, **over):
    import dataclasses

    s = dataclasses.replace(settings, **over)
    return Vault(RedisBackend(client, op_timeout_s=s.op_timeout_s, retries=s.retries, breaker=CircuitBreaker(s.breaker_threshold, s.breaker_cooldown_s), clock=clock), keyring, s)


REF = SessionRef("o", "s")


async def test_connection_errors_are_retried_once_then_reported_as_unavailable(settings, keyring, clock):
    r = BrokenRedis(rexc.ConnectionError("refused"))
    v = vault_on(r, settings, keyring, clock, retries=1)
    with pytest.raises(VaultUnavailable):
        await v.tokenize(REF, "NAME", "John Doe")
    assert r.calls == 2                                           # 1 attempt + 1 retry, no more


async def test_a_hung_redis_is_cut_off_by_the_timeout_not_waited_for(settings, keyring, clock):
    r = BrokenRedis(delay=5.0)
    v = vault_on(r, settings, keyring, clock, op_timeout_s=0.05, retries=0)
    t0 = time.perf_counter()
    with pytest.raises(VaultUnavailable):
        await v.resolve(REF, ["[TOK_NAME_1]"])
    assert time.perf_counter() - t0 < 1.0


async def test_non_transient_redis_errors_are_not_retried(settings, keyring, clock):
    r = BrokenRedis(rexc.ResponseError("OOM command not allowed"))
    v = vault_on(r, settings, keyring, clock, retries=3)
    with pytest.raises(VaultUnavailable):
        await v.tokenize(REF, "NAME", "John Doe")
    assert r.calls == 1


async def test_the_circuit_breaker_opens_after_repeated_failures_and_recovers(settings, keyring, clock):
    r = BrokenRedis(rexc.ConnectionError("down"))
    v = vault_on(r, settings, keyring, clock, retries=0, breaker_threshold=3, breaker_cooldown_s=0.2)
    for _ in range(3):
        with pytest.raises(VaultUnavailable):
            await v.resolve(REF, ["[TOK_NAME_1]"])
    assert r.calls == 3
    t0 = time.perf_counter()
    for _ in range(50):
        with pytest.raises(VaultUnavailable):
            await v.resolve(REF, ["[TOK_NAME_1]"])
    assert r.calls == 3                                            # open: Redis is not touched at all
    assert time.perf_counter() - t0 < 0.15                         # ...and rejecting is cheap
    assert not await v.ready()

    await asyncio.sleep(0.25)                                      # cool-down over: one probe is allowed through
    r.exc = None
    assert await v.ready() and r.calls == 4
    assert await v.resolve(REF, ["[TOK_NAME_1]"]) == {}            # closed again: normal operation


async def test_a_success_resets_the_failure_count():
    b = CircuitBreaker(3, 10.0)
    for step in (b.failure, b.failure, b.success, b.failure, b.failure):
        step()
    assert b.allow()
    b.failure()
    assert not b.allow()


async def test_breaker_uses_its_clock():
    now = [100.0]
    b = CircuitBreaker(1, 5.0, clock=lambda: now[0])
    b.failure()
    assert not b.allow()
    now[0] = 105.1
    assert b.allow()


async def test_streams_and_json_degrade_safely_when_the_vault_is_down(settings, keyring, clock):
    r = BrokenRedis(rexc.ConnectionError("down"))
    v = vault_on(r, settings, keyring, clock, retries=0)
    st = StreamState()
    assert await detokenize_stream("Hi [TOK_NAME_1] ", "s", vault=v, org_id="o", state=st) == "Hi [TOK_NAME_1] "
    assert st.degraded
    assert await detokenize_json({"a": "[TOK_NAME_1]"}, "s", vault=v, org_id="o", on_unavailable="passthrough") == {"a": "[TOK_NAME_1]"}
    with pytest.raises(VaultUnavailable):
        await detokenize_json({"a": "[TOK_NAME_1]"}, "s", vault=v, org_id="o")


async def test_a_slow_vault_never_stalls_other_concurrent_work(settings, keyring, clock):
    r = BrokenRedis(delay=5.0)
    v = vault_on(r, settings, keyring, clock, op_timeout_s=0.05, retries=0, breaker_threshold=1000)
    t0 = time.perf_counter()
    res = await asyncio.gather(*[v.resolve(REF, ["[TOK_NAME_1]"]) for _ in range(40)], return_exceptions=True)
    assert all(isinstance(x, VaultUnavailable) for x in res)
    assert time.perf_counter() - t0 < 1.0                           # 40 hung calls time out together, not one after another


async def test_a_token_missing_after_publish_fails_closed(make_vault, monkeypatch):
    """If the store loses a mapping between the lookup and the publish round trips (e.g. an expiry), tokenization must
    refuse (VaultUnavailable) rather than return a list with a hole where a token should be."""
    vault = make_vault()

    async def acknowledges_nothing(sid, entries):
        return []

    monkeypatch.setattr(vault._b, "publish", acknowledges_nothing)
    with pytest.raises(VaultUnavailable, match="inconsistent"):
        await vault.tokenize(SessionRef("org-1", "sess-1"), "EMAIL", "jane.doe@example.com")
