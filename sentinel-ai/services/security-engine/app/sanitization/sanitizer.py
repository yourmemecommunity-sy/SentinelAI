"""Sanitization: mask, redact, tokenize, hash. Overlapping detections are merged so no fragment survives.

Partial reveal (masking) is limited to identifiers where last-4 display is industry practice.
Secrets and credentials are never partially revealed, whatever the requested action.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Protocol

from app.models.types import Action, EntityType, Severity
from app.policies.evaluator import ResolvedDetection
from app.utils.hashing import value_digest

_LAST4_ENTITIES = {EntityType.CREDIT_CARD, EntityType.BANK_ACCOUNT, EntityType.AADHAAR, EntityType.SSN,
                   EntityType.PHONE}
_EMAIL = re.compile(r"^([^@\s])[^@\s]*(@.+)$")


class TokenVault(Protocol):
    """`token_for` returns None when this vault will not tokenize the value; the sanitizer then redacts it.
    A vault may also offer `prefetch(pairs)` to resolve every value in one round trip."""

    def token_for(self, entity: str, value: str) -> str | None: ...


@dataclass
class InMemoryTokenVault:
    """Per-request vault: same value -> same token; `restore` reverses tokens in a model response.

    The mapping holds raw values, so it must stay in process memory for the request lifetime only
    (a Redis-backed, TTL'd, encrypted implementation replaces this in the gateway). Never log it.
    """
    _counters: dict[str, int] = field(default_factory=dict)
    _forward: dict[tuple[str, str], str] = field(default_factory=dict)
    _reverse: dict[str, str] = field(default_factory=dict)

    def token_for(self, entity: str, value: str) -> str:
        key = (entity, value)
        if key not in self._forward:
            n = self._counters.get(entity, 0) + 1
            self._counters[entity] = n
            token = f"<{entity}_TOKEN_{n:03d}>"
            self._forward[key] = token
            self._reverse[token] = value
        return self._forward[key]

    def restore(self, text: str) -> str:
        for token, value in self._reverse.items():
            text = text.replace(token, value)
        return text


@dataclass(frozen=True)
class _Span:
    start: int
    end: int
    entity: EntityType
    action: Action
    members: int  # number of distinct entity types merged into this span


@dataclass(frozen=True)
class SanitizeResult:
    text: str
    applied: dict[tuple[EntityType, Action], int]


def _mask_last4(value: str) -> str:
    total = sum(c.isalnum() for c in value)
    seen = 0
    out = []
    for c in value:
        if c.isalnum():
            seen += 1
            out.append(c if seen > total - 4 else "*")
        else:
            out.append(c)
    return "".join(out)


def _replacement(span: _Span, value: str, vault: TokenVault | None) -> str:
    label = span.entity.value
    if span.action is Action.REDACT:
        return f"[{label}_REDACTED]"
    if span.action is Action.TOKENIZE:
        # Without a vault, tokens are one-way placeholders; fall back to redaction rather than leak.
        token = vault.token_for(label, value) if vault else None
        return token if token else f"[{label}_REDACTED]"
    if span.action is Action.HASH:
        return f"<{label}_HASH:{value_digest(label, value)[:8]}>"
    # MASK
    if span.members > 1:
        return f"[{label}_MASKED]"
    if span.entity is EntityType.EMAIL:
        m = _EMAIL.match(value)
        return f"{m.group(1)}***{m.group(2)}" if m else f"[{label}_MASKED]"
    if span.entity in _LAST4_ENTITIES and sum(c.isalnum() for c in value) >= 8:
        return _mask_last4(value)
    return f"[{label}_MASKED]"


def _merge(resolved: list[ResolvedDetection]) -> list[_Span]:
    items = sorted((r for r in resolved if r.action.sanitizes),
                   key=lambda r: (r.detection.location.start, -r.detection.location.end))
    spans: list[_Span] = []
    cur: list[ResolvedDetection] = []
    cur_end = -1

    def flush() -> None:
        if not cur:
            return
        primary = max(cur, key=lambda r: (r.severity.rank, r.detection.location.end - r.detection.location.start))
        action = max((r.action for r in cur), key=lambda a: a.rank)
        # Credentials/CRITICAL data are never partially revealed: escalate MASK/HASH to REDACT.
        if any(r.severity is Severity.CRITICAL for r in cur) and action in (Action.MASK, Action.HASH):
            action = Action.REDACT
        spans.append(_Span(min(r.detection.location.start for r in cur), max(r.detection.location.end for r in cur),
                           primary.detection.entity, action,
                           len({r.detection.entity for r in cur})))

    for r in items:
        s, e = r.detection.location.start, r.detection.location.end
        if cur and s < cur_end:
            cur.append(r)
            cur_end = max(cur_end, e)
        else:
            flush()
            cur, cur_end = [r], e
    flush()
    return spans


def sanitize(text: str, resolved: list[ResolvedDetection], vault: TokenVault | None = None) -> SanitizeResult:
    spans = _merge(resolved)
    applied: dict[tuple[EntityType, Action], int] = {}
    # Compute replacements left-to-right (so tokens number in reading order), apply right-to-left.
    prefetch = getattr(vault, "prefetch", None)
    if prefetch is not None:
        prefetch([(s.entity.value, text[s.start:s.end]) for s in spans if s.action is Action.TOKENIZE])
    replacements = [_replacement(span, text[span.start:span.end], vault) for span in spans]
    out = text
    for span, repl in zip(reversed(spans), reversed(replacements)):
        out = out[:span.start] + repl + out[span.end:]
        applied[(span.entity, span.action)] = applied.get((span.entity, span.action), 0) + 1
    return SanitizeResult(out, applied)
