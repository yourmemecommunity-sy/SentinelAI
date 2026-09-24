from __future__ import annotations

from typing import Any

import redis.asyncio as aioredis

from app.backend import CircuitBreaker, RedisBackend
from app.config.settings import Settings
from app.crypto import KeyRing
from app.vault import Vault


def build_fake_client(s: Settings, server: Any = None) -> aioredis.Redis:
    """In-memory fakeredis client for development/tests (Settings refuses the memory backend in production), with the same
    bounded, blocking pool as a real deployment. fakeredis otherwise uses redis-py's default pool, which since redis-py 8
    caps at 100 connections and RAISES beyond that - so a burst failed tokenization closed where production would queue.
    fakeredis is imported lazily so the production image does not need it."""
    from fakeredis import FakeAsyncRedis, FakeServer

    client = FakeAsyncRedis(server=server or FakeServer(), connection_pool_class=aioredis.BlockingConnectionPool,
                            max_connections=s.redis_max_connections)
    pool = client.connection_pool
    if isinstance(pool, aioredis.BlockingConnectionPool):
        pool.timeout = s.op_timeout_s  # fakeredis does not forward `timeout`; bound the wait for a connection as production does
    return client


def build_client(s: Settings) -> aioredis.Redis:
    if s.backend == "memory":
        return build_fake_client(s)
    # A BOUNDED, BLOCKING pool. With the default pool, concurrency above its limit raises MaxConnectionsError, which is a
    # ConnectionError subclass and would therefore be treated as an outage: a burst of traffic would fail every tokenizing
    # request closed. Blocking makes callers queue for a connection instead; the per-operation timeout still bounds the wait,
    # so a genuinely overloaded vault still fails closed rather than hanging. (Found by running against a real Redis server.)
    pool = aioredis.BlockingConnectionPool.from_url(
        s.redis_url, max_connections=s.redis_max_connections, timeout=s.op_timeout_s,
        socket_timeout=s.op_timeout_s, socket_connect_timeout=s.connect_timeout_s,
        health_check_interval=30, decode_responses=False,
    )
    return aioredis.Redis(connection_pool=pool)


def build_vault(s: Settings, keyring: KeyRing, client: aioredis.Redis | None = None) -> tuple[Vault, aioredis.Redis]:
    client = client or build_client(s)
    backend = RedisBackend(client, op_timeout_s=s.op_timeout_s, retries=s.retries,
                           breaker=CircuitBreaker(s.breaker_threshold, s.breaker_cooldown_s))
    return Vault(backend, keyring, s), client
