"""Session-scoped token vaults for the sanitizer.

`RemoteTokenVault` asks the token-vault service (Redis-backed, encrypted, TTL'd) for tokens, so a model's reply can later be
de-tokenized in the same session. Only allow-listed entity types are ever tokenized: for anything the vault refuses (credentials,
secrets, cards) the sanitizer falls back to redaction. If the vault cannot be reached the scan FAILS CLOSED: silently degrading to a
different action than the policy asked for would hide an outage.

Uses only the standard library (no new runtime dependency), never follows redirects (the internal token must not be forwarded), and
never logs or echoes values.
"""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from collections.abc import Sequence
from typing import Any

_TOKEN = re.compile(r"\[TOK_[A-Z](?:[A-Z_]{0,30}[A-Z])?_[0-9]{1,6}\]")


class VaultUnavailableError(Exception):
    """The vault could not be used. The message never contains a value."""


class NullVault:
    """Used when a request names a vault session but no vault is configured: every TOKENIZE becomes REDACT."""

    def token_for(self, entity: str, value: str) -> str | None:
        return None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:  # noqa: D401 - never follow a redirect
        return None


class RemoteTokenVault:
    def __init__(self, base_url: str, token: str | None, organization_id: str, session_id: str, timeout_s: float = 0.5) -> None:
        self._url = base_url.rstrip("/") + "/v1/vault/tokenize"
        self._token = token
        self._org = organization_id
        self._session = session_id
        self._timeout = timeout_s
        self._opener = urllib.request.build_opener(_NoRedirect())
        self._cache: dict[tuple[str, str], str | None] = {}

    def prefetch(self, pairs: Sequence[tuple[str, str]]) -> None:
        """One round trip for every distinct (entity, value) about to be tokenized."""
        wanted = [p for p in dict.fromkeys(pairs) if p not in self._cache]
        if not wanted:
            return
        tokens = self._call(wanted)
        for pair, tok in zip(wanted, tokens):
            self._cache[pair] = tok

    def token_for(self, entity: str, value: str) -> str | None:
        key = (entity, value)
        if key not in self._cache:
            self.prefetch([key])
        return self._cache[key]

    def _call(self, pairs: Sequence[tuple[str, str]]) -> list[str | None]:
        body = json.dumps({"organization_id": self._org, "session_id": self._session, "refuse": "null",
                           "items": [{"entity": e, "value": v} for e, v in pairs]}).encode()
        headers = {"content-type": "application/json", **({"x-internal-token": self._token} if self._token else {})}
        req = urllib.request.Request(self._url, data=body, headers=headers, method="POST")
        try:
            with self._opener.open(req, timeout=self._timeout) as res:
                if res.status != 200:
                    raise VaultUnavailableError(f"vault_http_{res.status}")
                data = json.loads(res.read(1_000_000))
        except urllib.error.HTTPError as e:
            raise VaultUnavailableError(f"vault_http_{e.code}") from None
        except (urllib.error.URLError, TimeoutError, OSError):
            raise VaultUnavailableError("vault_unreachable") from None
        except ValueError:
            raise VaultUnavailableError("vault_invalid_response") from None
        tokens = data.get("tokens") if isinstance(data, dict) else None
        if not isinstance(tokens, list) or len(tokens) != len(pairs) or not all(t is None or (isinstance(t, str) and _TOKEN.fullmatch(t)) for t in tokens):
            raise VaultUnavailableError("vault_invalid_response")
        return tokens
