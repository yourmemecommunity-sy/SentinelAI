"""Key hierarchy and value sealing.

master key --HKDF(salt = H(org, session), info = purpose)--> per-session keys:
  * ``mac``: HMAC-SHA256 key that turns a value into its lookup digest (the Redis field name). Without the key the digest
    cannot be recomputed from a guessed value, so the Redis keyspace does not reveal *which* value a token stands for.
  * ``enc``: AES-256-GCM key that seals the value itself. The token is the AAD, so a sealed blob cannot be moved to another token.

Because keys are per session, the same value in another session (or another tenant) yields an unrelated digest and an
unrelated ciphertext: a token is meaningless outside the session that minted it.
"""
from __future__ import annotations

import hashlib
import hmac
import os
from collections import OrderedDict
from dataclasses import dataclass
from typing import Mapping

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_INFO = b"sentinelai-vault-v1"
_MAX_CACHED = 512


@dataclass(frozen=True, slots=True)
class SessionKeys:
    kid: str
    enc: bytes
    mac: bytes


class KeyRing:
    """Master keys by id. New sessions use `active`; older ids stay so sessions minted before a rotation remain readable
    for their remaining lifetime (a session is pinned to the key id it was created with)."""

    def __init__(self, keys: Mapping[str, bytes], active: str) -> None:
        if active not in keys:
            raise ValueError("active key id is not in the key ring")
        for kid, k in keys.items():
            if not kid.isascii() or not 1 <= len(kid) <= 8 or not kid.isalnum():
                raise ValueError("key ids must be 1-8 ascii alphanumerics")
            if len(k) < 32:
                raise ValueError("master keys must be at least 32 bytes")
        self._keys = dict(keys)
        self.active = active
        self._cache: OrderedDict[tuple[str, bytes], SessionKeys] = OrderedDict()

    def has(self, kid: str) -> bool:
        return kid in self._keys

    def session_keys(self, kid: str, session_hash: bytes) -> SessionKeys:
        ck = (kid, session_hash)
        hit = self._cache.get(ck)
        if hit is not None:
            self._cache.move_to_end(ck)
            return hit
        master = self._keys.get(kid)
        if master is None:
            raise KeyError("unknown key id")
        okm = HKDF(algorithm=SHA256(), length=64, salt=session_hash, info=_INFO).derive(master)
        keys = SessionKeys(kid, okm[:32], okm[32:])
        self._cache[ck] = keys
        if len(self._cache) > _MAX_CACHED:
            self._cache.popitem(last=False)
        return keys

    @staticmethod
    def random() -> "KeyRing":
        """Ephemeral development key ring: every restart makes existing sessions unreadable (which is also a safe default)."""
        return KeyRing({"dev": os.urandom(32)}, "dev")


def session_hash(org_id: str, session_id: str) -> bytes:
    return hashlib.sha256(f"{org_id}\x00{session_id}".encode()).digest()


def digest(keys: SessionKeys, entity: str, normalized: str) -> str:
    """Lookup key for a value inside a session (128-bit HMAC-SHA256 prefix, hex)."""
    return hmac.new(keys.mac, f"{entity}\x00{normalized}".encode(), hashlib.sha256).hexdigest()[:32]


def seal(keys: SessionKeys, token: str, value: str) -> bytes:
    nonce = os.urandom(12)
    kid = keys.kid.encode()
    return bytes([len(kid)]) + kid + nonce + AESGCM(keys.enc).encrypt(nonce, value.encode(), token.encode())


def open_sealed(keys: SessionKeys, token: str, blob: bytes) -> str | None:
    """None (never an exception) for anything that does not authenticate: wrong key, moved blob, corruption."""
    k = blob[0] if blob else 0
    if k == 0 or len(blob) < 1 + k + 12 + 16:
        return None
    nonce = blob[1 + k:13 + k]
    try:
        return AESGCM(keys.enc).decrypt(nonce, blob[13 + k:], token.encode()).decode()
    except (InvalidTag, UnicodeDecodeError):
        return None
