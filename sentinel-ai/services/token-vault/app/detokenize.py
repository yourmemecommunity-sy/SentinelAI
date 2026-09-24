"""De-tokenization: structured JSON and streaming text.

`detokenize_json` collects every distinct token in a payload, resolves them with ONE batched Redis round trip, then rebuilds the
payload. `detokenize_stream` is a small state machine: it emits everything that can no longer become a token immediately, and
holds back only a trailing ``[`` prefix (at most MAX_TOKEN_LEN-1 characters). It never buffers the stream.

Failure policy: when the vault is unreachable, hydration is skipped rather than guessed. Leaving a token in the text is the safe
direction (no plaintext is released), so streams degrade instead of breaking; JSON callers can choose to raise instead.
Only string VALUES are hydrated; dict keys never are.
"""
from __future__ import annotations

from collections import OrderedDict
from collections.abc import Iterable
from typing import Any, Literal, Protocol

from app.errors import VaultUnavailable
from app.tokens import MAX_TOKEN_LEN, TOKEN_RE, is_token_prefix
from app.vault import SessionRef


class TokenResolver(Protocol):
    """What de-tokenization needs from a vault: token -> plaintext for one session (app.vault.Vault implements it)."""

    async def resolve(self, ref: SessionRef, tokens: Iterable[str]) -> dict[str, str]: ...

OnUnavailable = Literal["raise", "passthrough"]
MAX_DEPTH = 64
MAX_NODES = 200_000
MAX_STREAM_LOOKUPS = 512     # distinct tokens one stream may ask about: a model emitting guessed tokens cannot amplify into Redis load
_MAX_CACHE = 1024


class StreamState:
    """Per-stream state: the held-back partial token and a bounded cache of resolutions. Drop it when the stream ends."""

    __slots__ = ("carry", "cache", "lookups", "degraded")

    def __init__(self) -> None:
        self.carry = ""
        self.cache: OrderedDict[str, str | None] = OrderedDict()   # None = looked up, not resolvable (negative cache)
        self.lookups = 0
        self.degraded = False                                      # True once hydration was skipped for lack of the vault

    def remember(self, token: str, value: str | None) -> None:
        self.cache[token] = value
        if len(self.cache) > _MAX_CACHE:
            self.cache.popitem(last=False)


# ------------------------------------------------------------------ JSON
def _collect(root: Any) -> set[str]:
    tokens: set[str] = set()
    stack: list[tuple[Any, int]] = [(root, 0)]
    nodes = 0
    while stack:
        node, depth = stack.pop()
        nodes += 1
        if nodes > MAX_NODES or depth > MAX_DEPTH:
            raise ValueError("payload too large or too deeply nested")
        if isinstance(node, str):
            if "[TOK_" in node:
                tokens.update(m.group(0) for m in TOKEN_RE.finditer(node))
        elif isinstance(node, dict):
            stack.extend((v, depth + 1) for v in node.values())
        elif isinstance(node, list):
            stack.extend((v, depth + 1) for v in node)
    return tokens


def _rebuild(node: Any, values: dict[str, str]) -> Any:
    if isinstance(node, str):
        return TOKEN_RE.sub(lambda m: values.get(m.group(0), m.group(0)), node) if "[TOK_" in node else node
    if isinstance(node, dict):
        return {k: _rebuild(v, values) for k, v in node.items()}
    if isinstance(node, list):
        return [_rebuild(v, values) for v in node]
    return node


async def detokenize_json(
    payload: dict[str, Any], session_id: str, *, vault: TokenResolver, org_id: str, on_unavailable: OnUnavailable = "raise",
) -> dict[str, Any]:
    """Map tokens in a structured payload back to their true values. The input is never mutated.
    Unknown, expired and other-session tokens are left exactly as they were."""
    tokens = _collect(payload)
    if not tokens:
        return payload
    try:
        values = await vault.resolve(SessionRef(org_id, session_id), tokens)
    except VaultUnavailable:
        if on_unavailable == "raise":
            raise
        return payload
    return _rebuild(payload, values) if values else payload


# ------------------------------------------------------------------ streaming
async def detokenize_stream(
    chunk: str, session_id: str, *, vault: TokenResolver, org_id: str, state: StreamState | None = None,
    final: bool = False, on_unavailable: OnUnavailable = "passthrough",
) -> str:
    """Hydrate tokens in one chunk of a text stream.

    Pass the SAME `state` for every chunk of a stream: a token split across chunks (``...[TO`` | ``K_NAME_1]...``) is held
    back until it completes. With `state=None` each call is independent (a split token would not be recognised), which is
    only appropriate for whole messages. Call once more with ``final=True`` (any chunk, possibly empty) to flush the carry.
    """
    st = state if state is not None else StreamState()
    text = st.carry + chunk

    matches = list(TOKEN_RE.finditer(text)) if "[TOK_" in text else []
    fresh = [t for t in dict.fromkeys(m.group(0) for m in matches) if t not in st.cache]
    if fresh:
        room = max(0, MAX_STREAM_LOOKUPS - st.lookups)
        ask, skip = fresh[:room], fresh[room:]
        for t in skip:
            st.remember(t, None)
        if ask:
            try:
                found = await vault.resolve(SessionRef(org_id, session_id), ask)
            except VaultUnavailable:
                if on_unavailable == "raise":
                    raise
                st.degraded = True
                found = {}
                # Not cached: a later chunk may succeed once the vault recovers.
                for t in ask:
                    st.cache.pop(t, None)
                ask = []
            st.lookups += len(ask)
            for t in ask:
                st.remember(t, found.get(t))

    out: list[str] = []
    pos = 0
    for m in matches:
        out.append(text[pos:m.start()])
        tok = m.group(0)
        value = st.cache.get(tok)
        out.append(tok if value is None else value)
        pos = m.end()
    rest = text[pos:]
    st.carry = ""
    if not final:
        i = rest.rfind("[")
        if i != -1 and is_token_prefix(rest[i:]):
            st.carry = rest[i:]
            rest = rest[:i]
    out.append(rest)
    return "".join(out)


__all__ = ["StreamState", "detokenize_json", "detokenize_stream", "MAX_TOKEN_LEN"]
