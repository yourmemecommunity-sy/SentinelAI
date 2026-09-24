from __future__ import annotations

import base64
import binascii
import os
from dataclasses import dataclass

from app.crypto import KeyRing

MAX_TTL_SECONDS = 86_400


@dataclass(frozen=True)
class Settings:
    environment: str = "development"
    internal_token: str | None = None
    backend: str = "redis"                  # "redis" | "memory" (fakeredis; development/tests only)
    redis_url: str = "redis://localhost:6379/0"
    ttl_seconds: int = 3600                  # retention mandate: absolute lifetime of a session's mappings
    max_tokens_per_session: int = 10_000
    max_value_bytes: int = 8_192
    max_batch: int = 512
    max_body_bytes: int = 1_048_576
    redis_max_connections: int = 64          # bounded, blocking pool: bursts queue instead of failing closed
    op_timeout_s: float = 0.25               # per Redis round trip
    connect_timeout_s: float = 0.5
    retries: int = 1                         # extra attempts after a transient failure
    breaker_threshold: int = 5               # consecutive failed operations before fast-failing
    breaker_cooldown_s: float = 2.0
    ephemeral_keys: bool = False             # True when no master key was configured (development only)

    @classmethod
    def from_env(cls) -> tuple["Settings", KeyRing]:
        e = os.environ.get
        env = e("SENTINEL_ENV", "development")
        prod = env == "production"
        s = cls(
            environment=env,
            internal_token=e("VAULT_TOKEN") or None,
            backend=e("VAULT_BACKEND", "redis"),
            redis_url=e("REDIS_URL", "redis://localhost:6379/0"),
            redis_max_connections=int(e("VAULT_REDIS_MAX_CONNECTIONS", "64")),
            ttl_seconds=int(e("VAULT_TTL_SECONDS", "3600")),
            max_tokens_per_session=int(e("VAULT_MAX_TOKENS", "10000")),
            max_value_bytes=int(e("VAULT_MAX_VALUE_BYTES", "8192")),
            max_batch=int(e("VAULT_MAX_BATCH", "512")),
            op_timeout_s=float(e("VAULT_OP_TIMEOUT_S", "0.25")),
            connect_timeout_s=float(e("VAULT_CONNECT_TIMEOUT_S", "0.5")),
            retries=int(e("VAULT_RETRIES", "1")),
            ephemeral_keys=not e("VAULT_MASTER_KEYS"),
        )
        if not 1 <= s.ttl_seconds <= MAX_TTL_SECONDS:
            raise RuntimeError(f"VAULT_TTL_SECONDS must be between 1 and {MAX_TTL_SECONDS}")
        if s.backend not in ("redis", "memory"):
            raise RuntimeError("VAULT_BACKEND must be 'redis' or 'memory'")
        if prod:
            # Fail closed on misconfiguration: never run an unauthenticated vault, an in-memory fake, or throwaway keys in production.
            if not s.internal_token or len(s.internal_token) < 16:
                raise RuntimeError("VAULT_TOKEN (>= 16 chars) must be set when SENTINEL_ENV=production")
            if s.backend != "redis":
                raise RuntimeError("production requires VAULT_BACKEND=redis")
            if s.ephemeral_keys:
                raise RuntimeError("VAULT_MASTER_KEYS must be set when SENTINEL_ENV=production")
        return s, _keyring(e("VAULT_MASTER_KEYS"), e("VAULT_ACTIVE_KEY"))


def _keyring(raw: str | None, active: str | None) -> KeyRing:
    """VAULT_MASTER_KEYS="k1:<base64>,k2:<base64>" (each >= 32 bytes). VAULT_ACTIVE_KEY defaults to the first id."""
    if not raw:
        return KeyRing.random()
    keys: dict[str, bytes] = {}
    for part in raw.split(","):
        kid, _, b64 = part.strip().partition(":")
        try:
            keys[kid] = base64.b64decode(b64, validate=True)
        except (binascii.Error, ValueError):
            raise RuntimeError("VAULT_MASTER_KEYS is malformed") from None  # never echo the value
    return KeyRing(keys, active or next(iter(keys)))
