"""Redis schema and resilient I/O. Nothing here knows what a value is: it moves opaque strings and sealed bytes.

Schema (one session = three Hashes sharing a hash tag, so Redis Cluster keeps them on one shard):

  sentinel:vault:v1:{<sid>}:fwd    HASH  field = HMAC digest of (type, normalized value)   value = token
  sentinel:vault:v1:{<sid>}:rev    HASH  field = token                                     value = sealed value (AES-256-GCM)
  sentinel:vault:v1:{<sid>}:meta   HASH  kid, created, deadline, ctr:<TYPE> counters

<sid> = SHA-256(org, session) truncated: user-supplied ids never appear in the keyspace. Every write re-applies EXPIREAT with the
*absolute* deadline fixed when the session was created, so activity can never extend retention beyond ttl_seconds.
"""
from __future__ import annotations

import asyncio
import random
import time
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from typing import Any, TypeVar

import redis.asyncio as aioredis
from redis import exceptions as rexc

from app.errors import VaultUnavailable

T = TypeVar("T")


def _text(v: bytes | str) -> str:
    """Redis replies are bytes unless a client is created with decode_responses=True; accept both, never crash on str."""
    return v.decode() if isinstance(v, bytes) else v


def _bytes(v: bytes | str) -> bytes:
    return v if isinstance(v, bytes) else v.encode()
PREFIX = "sentinel:vault:v1"
_TRANSIENT = (asyncio.TimeoutError, TimeoutError, rexc.ConnectionError, rexc.TimeoutError, rexc.BusyLoadingError, OSError)


def key(sid: str, part: str) -> str:
    return f"{PREFIX}:{{{sid}}}:{part}"


@dataclass(frozen=True, slots=True)
class Meta:
    kid: str
    deadline: float


class CircuitBreaker:
    """After `threshold` consecutive failed operations, reject immediately for `cooldown_s` instead of stacking timeouts
    (a dead Redis must cost microseconds per request, not op_timeout x retries)."""

    def __init__(self, threshold: int, cooldown_s: float, clock: Callable[[], float] = time.monotonic) -> None:
        self._threshold, self._cooldown, self._clock = threshold, cooldown_s, clock
        self._failures = 0
        self._open_until = 0.0

    def allow(self) -> bool:
        return self._clock() >= self._open_until

    def success(self) -> None:
        self._failures = 0

    def failure(self) -> None:
        self._failures += 1
        if self._failures >= self._threshold:
            self._open_until = self._clock() + self._cooldown


class RedisBackend:
    def __init__(self, client: aioredis.Redis, *, op_timeout_s: float, retries: int, breaker: CircuitBreaker,
                 clock: Callable[[], float] = time.time) -> None:
        self._r = client
        self._timeout = op_timeout_s
        self._retries = retries
        self._breaker = breaker
        self.now = clock

    async def _run(self, op: Callable[[], Awaitable[T]]) -> T:
        if not self._breaker.allow():
            raise VaultUnavailable("vault store unavailable (circuit open)")
        for attempt in range(self._retries + 1):
            try:
                async with asyncio.timeout(self._timeout):
                    out = await op()
                self._breaker.success()
                return out
            except _TRANSIENT:
                if attempt < self._retries:
                    await asyncio.sleep(random.uniform(0.005, 0.03))  # jitter so replicas do not retry in lockstep
            except rexc.RedisError:
                break  # not transient (e.g. OOM, wrong type): retrying cannot help
        self._breaker.failure()
        raise VaultUnavailable("vault store unavailable")

    async def ping(self) -> bool:
        try:
            return bool(await self._run(lambda: self._r.ping()))
        except VaultUnavailable:
            return False

    # ------------------------------------------------------------------ session lifecycle
    async def open_session(self, sid: str, kid: str, ttl_s: int) -> Meta:
        """Create the session meta on first use (kid + absolute deadline) and return what is stored, whoever won the race."""
        mk = key(sid, "meta")
        deadline = self.now() + ttl_s

        async def op() -> list[Any]:
            async with self._r.pipeline(transaction=False) as p:
                p.hsetnx(mk, "kid", kid)
                p.hsetnx(mk, "deadline", repr(deadline))
                p.hmget(mk, "kid", "deadline")
                result: list[Any] = (await p.execute())[-1]
                return result

        got = await self._run(op)
        return Meta(_text(got[0]), float(got[1]))

    async def get_meta(self, sid: str) -> Meta | None:
        got = await self._run(lambda: self._r.hmget(key(sid, "meta"), "kid", "deadline"))
        return None if got[0] is None or got[1] is None else Meta(_text(got[0]), float(got[1]))

    async def expire_at(self, sid: str, deadline: float) -> None:
        at = int(deadline) + 1

        async def op() -> None:
            async with self._r.pipeline(transaction=False) as p:
                for part in ("fwd", "rev", "meta"):
                    p.expireat(key(sid, part), at)
                await p.execute()

        await self._run(op)

    async def delete_session(self, sid: str) -> None:
        await self._run(lambda: self._r.delete(*(key(sid, p) for p in ("fwd", "rev", "meta"))))

    # ------------------------------------------------------------------ mappings
    async def lookup(self, sid: str, digests: Sequence[str]) -> list[str | None]:
        got = await self._run(lambda: self._r.hmget(key(sid, "fwd"), list(digests)))
        return [None if g is None else _text(g) for g in got]

    async def count(self, sid: str) -> int:
        return int(await self._run(lambda: self._r.hlen(key(sid, "rev"))))

    async def reserve_numbers(self, sid: str, entity: str, k: int) -> int:
        """Atomically reserve k consecutive numbers; returns the first. (INCRBY is atomic, so concurrent writers never overlap.)"""
        last = int(await self._run(lambda: self._r.hincrby(key(sid, "meta"), f"ctr:{entity}", k)))
        return last - k + 1

    async def publish(self, sid: str, entries: Sequence[tuple[str, str, bytes]]) -> list[str]:
        """entries = (digest, token, sealed). Returns the winning token for each digest (another writer may have won the race)."""
        fwd, rev = key(sid, "fwd"), key(sid, "rev")

        async def write() -> list[Any]:
            async with self._r.pipeline(transaction=False) as p:
                for digest, token, sealed in entries:
                    p.hsetnx(rev, token, sealed)      # reverse first: a forward entry must never point at a missing value
                    p.hsetnx(fwd, digest, token)
                return await p.execute()

        res = await self._run(write)
        won = [bool(res[2 * i + 1]) for i in range(len(entries))]
        if all(won):
            return [t for _, t, _ in entries]

        async def settle() -> list[Any]:
            async with self._r.pipeline(transaction=False) as p:
                for (digest, token, _), w in zip(entries, won):
                    if not w:
                        p.hdel(rev, token)            # our sealed copy is orphaned
                        p.hget(fwd, digest)
                return await p.execute()

        winners = iter(r for i, r in enumerate(await self._run(settle)) if i % 2 == 1)
        out: list[str] = []
        for (_, t, _), w in zip(entries, won):
            if w:
                out.append(t)
                continue
            theirs = next(winners)
            if theirs is None:  # the winner's mapping vanished between the two round trips (expiry): do not guess
                raise VaultUnavailable("vault store inconsistent")
            out.append(_text(theirs))
        return out

    async def fetch_sealed(self, sid: str, tokens: Sequence[str]) -> list[bytes | None]:
        got = await self._run(lambda: self._r.hmget(key(sid, "rev"), list(tokens)))
        return [None if g is None else _bytes(g) for g in got]
