"""The vault: deterministic per-session tokenization over the Redis schema in `backend`.

Properties (each has a test):
  * deterministic inside a session: the same (type, value) always yields the same token, even under concurrent writers;
  * unlinkable outside it: digests and ciphertexts are keyed per (tenant, session), so the same value elsewhere looks unrelated;
  * values are encrypted at rest (a Redis dump reveals no plaintext), retention is an absolute deadline, and only allow-listed
    entity types can ever be stored (credentials and secrets are refused).
"""
from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from app.backend import RedisBackend
from app.config.settings import Settings
from app.crypto import KeyRing, SessionKeys, digest, open_sealed, seal, session_hash
from app.errors import TokenizationRefused, VaultLimitExceeded, VaultUnavailable
from app.tokens import TOKENIZABLE, is_token, make_token, normalize, require_tokenizable

_ID = re.compile(r"[A-Za-z0-9_.:@-]{1,128}")


@dataclass(frozen=True, slots=True)
class SessionRef:
    org_id: str
    session_id: str

    def __post_init__(self) -> None:
        if not _ID.fullmatch(self.org_id) or not _ID.fullmatch(self.session_id):  # fullmatch: '$' would accept a trailing newline
            raise TokenizationRefused("invalid organization or session id")

    @property
    def sid(self) -> str:
        return session_hash(self.org_id, self.session_id).hex()[:40]


class Vault:
    def __init__(self, backend: RedisBackend, keyring: KeyRing, settings: Settings) -> None:
        self._b, self._ring, self._s = backend, keyring, settings

    async def ready(self) -> bool:
        return await self._b.ping()

    def _keys(self, kid: str, ref: SessionRef) -> SessionKeys:
        return self._ring.session_keys(kid, session_hash(ref.org_id, ref.session_id))

    # ------------------------------------------------------------------ tokenize
    async def tokenize(self, ref: SessionRef, entity: str, value: str) -> str:
        return (await self.tokenize_many(ref, [(entity, value)]))[0]

    async def tokenize_many(self, ref: SessionRef, items: Sequence[tuple[str, str]]) -> list[str]:
        """Tokens for (entity, value) pairs, in order. Raises TokenizationRefused / VaultLimitExceeded / VaultUnavailable."""
        if not items:
            return []
        if len(items) > self._s.max_batch:
            raise VaultLimitExceeded("batch too large")
        for entity, value in items:
            require_tokenizable(entity)
            if not value.strip():
                raise TokenizationRefused("empty value")
            if len(value.encode()) > self._s.max_value_bytes:
                raise VaultLimitExceeded("value too large")

        sid = ref.sid
        meta = await self._b.open_session(sid, self._ring.active, self._s.ttl_seconds)
        if meta.deadline <= self._b.now():          # expired but not yet evicted by Redis: start a fresh session
            await self._b.delete_session(sid)
            meta = await self._b.open_session(sid, self._ring.active, self._s.ttl_seconds)
        if not self._ring.has(meta.kid):
            raise TokenizationRefused("session key unavailable")
        keys = self._keys(meta.kid, ref)

        digests = [digest(keys, e, normalize(e, v)) for e, v in items]
        found = await self._b.lookup(sid, list(dict.fromkeys(digests)))
        known = dict(zip(dict.fromkeys(digests), found))

        # First-seen order, one new token per distinct digest.
        pending: dict[str, tuple[str, str]] = {}
        for d, (e, v) in zip(digests, items):
            if known[d] is None and d not in pending:
                pending[d] = (e, v)
        if pending:
            if await self._b.count(sid) + len(pending) > self._s.max_tokens_per_session:
                raise VaultLimitExceeded("session token limit reached")
            per_entity: dict[str, list[str]] = {}
            for d, (e, _v) in pending.items():
                per_entity.setdefault(e, []).append(d)
            entries: list[tuple[str, str, bytes]] = []
            for e, ds in per_entity.items():
                first = await self._b.reserve_numbers(sid, e, len(ds))
                for i, d in enumerate(ds):
                    token = make_token(e, first + i)
                    entries.append((d, token, seal(keys, token, pending[d][1])))
            for (d, _t, _s), winner in zip(entries, await self._b.publish(sid, entries)):
                known[d] = winner
            await self._b.expire_at(sid, meta.deadline)
        # Every digest is now either one that already had a token or one just published. A gap means the store lost
        # data between the round trips (e.g. an expiry): fail closed rather than hand back a missing token.
        tokens: list[str] = []
        for d in digests:
            digest_token = known[d]
            if digest_token is None:
                raise VaultUnavailable("vault store inconsistent")
            tokens.append(digest_token)
        return tokens

    async def tokenize_partial(self, ref: SessionRef, items: Sequence[tuple[str, str]]) -> list[str | None]:
        """Like tokenize_many, but entity types that may never be tokenized yield None instead of failing the batch.
        (Callers such as the engine then fall back to redaction for exactly those values.)"""
        ok = [i for i, (e, _v) in enumerate(items) if e in TOKENIZABLE]
        got = await self.tokenize_many(ref, [items[i] for i in ok]) if ok else []
        out: list[str | None] = [None] * len(items)
        for i, t in zip(ok, got):
            out[i] = t
        return out

    # ------------------------------------------------------------------ resolve
    async def resolve(self, ref: SessionRef, tokens: Iterable[str]) -> dict[str, str]:
        """token -> plaintext for the tokens this session knows. Unknown/expired/foreign tokens are simply absent
        (indistinguishable from each other, so a caller cannot probe which tokens exist elsewhere)."""
        wanted = list(dict.fromkeys(t for t in tokens if is_token(t)))[: self._s.max_batch]
        if not wanted:
            return {}
        sid = ref.sid
        meta = await self._b.get_meta(sid)
        if meta is None or meta.deadline <= self._b.now() or not self._ring.has(meta.kid):
            return {}
        keys = self._keys(meta.kid, ref)
        out: dict[str, str] = {}
        for token, blob in zip(wanted, await self._b.fetch_sealed(sid, wanted)):
            if blob:
                value = open_sealed(keys, token, blob)
                if value is not None:
                    out[token] = value
        return out

    async def delete_session(self, ref: SessionRef) -> None:
        await self._b.delete_session(ref.sid)
