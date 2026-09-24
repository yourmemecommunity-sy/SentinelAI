"""Deterministic prompt-injection / jailbreak / exfiltration detector.

Hardening property: this detector is pure pattern matching. No model is asked to "judge" the text,
so attacker-controlled content cannot instruct the classifier itself.

Layers (each reports offsets in the ORIGINAL text):
  direct      - rule match on the raw text
  obfuscated  - rule match after Unicode normalization (fullwidth, homoglyphs, zero-width, combining
                marks), leetspeak folding, spaced-letter collapsing, reversal, and ROT13
  encoded     - rule match on decoded base64 / hex / percent-encoded runs
Not implemented: ML-assisted classification (see roadmap); semantic paraphrase attacks can evade rules.
"""
from __future__ import annotations

import base64
import binascii
import codecs
import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import unquote

from app.detectors.base import Detector, make_detection
from app.models.types import Detection, EntityType, Severity

_ZERO_WIDTH = {0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x00AD, 0x180E}
# Common Cyrillic/Greek look-alikes folded to Latin.
_HOMOGLYPHS = {ord(k): v for k, v in {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "һ": "h", "к": "k", "м": "m",
    "т": "t", "в": "b", "н": "h", "ο": "o", "ν": "v", "ι": "i", "α": "a",
    "ε": "e", "ı": "i",
}.items()}
_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "!": "i"})
_SPACED_RUN = re.compile(r"(?:\b[A-Za-z]\b[ \t._-])+\b[A-Za-z]\b")


@dataclass(frozen=True)
class _Rule:
    sub: str  # direct-layer sublabel used in the detector name
    entity: EntityType
    severity: Severity
    confidence: float
    regex: re.Pattern[str]


def _r(sub: str, entity: EntityType, conf: float, pattern: str, flags: int = re.IGNORECASE,
       severity: Severity = Severity.HIGH) -> _Rule:
    return _Rule(sub, entity, severity, conf, re.compile(pattern, flags))


_RULES: list[_Rule] = [
    # -- instruction override
    _r("direct", EntityType.PROMPT_INJECTION, 0.96,
       r"\b(?:ignore|disregard|forget|override|bypass|discard|skip)\b[^.\n]{0,40}?\b(?:previous|prior|above|earlier|preceding|all|any|your|these|those|system)\b[^.\n]{0,40}?\b(?:instructions?|prompts?|rules?|guidelines?|directives?|constraints?|guardrails?|polic(?:y|ies)|restrictions?|training)\b"),
    _r("direct", EntityType.PROMPT_INJECTION, 0.9,
       r"\b(?:ignore|disregard|forget)\b[^.\n]{0,30}?\b(?:instructions?|prompts?|rules?)\b[^.\n]{0,20}?\b(?:above|before|earlier|previous(?:ly)?|given)\b"),
    # -- system prompt extraction
    _r("direct", EntityType.SYSTEM_PROMPT_EXTRACTION, 0.94,
       r"\b(?:reveal|show|print|repeat|output|display|leak|disclose|tell\s+me|give\s+me|what\s+(?:is|are|were))\b[^.\n]{0,40}?\b(?:system|initial|hidden|original|developer|secret)\s+(?:prompt|instructions?|message|rules)\b"),
    _r("direct", EntityType.SYSTEM_PROMPT_EXTRACTION, 0.9,
       r"\brepeat\b[^.\n]{0,20}\b(?:words|text|everything|instructions)\b[^.\n]{0,20}\babove\b"),
    _r("direct", EntityType.SYSTEM_PROMPT_EXTRACTION, 0.85,
       r"\bwhat\s+(?:were|was)\s+you\s+(?:told|instructed|programmed)\b"),
    # -- jailbreak / role hijack
    _r("direct", EntityType.JAILBREAK, 0.92,
       r"\byou\s+are\s+now\b[^.\n]{0,40}\b(?:free|unrestricted|unfiltered|jailbroken|DAN|no\s+(?:rules|restrictions|limits))"),
    _r("direct", EntityType.JAILBREAK, 0.92,
       r"\b(?:act|behave|respond)\s+as\s+(?:if\s+you\s+(?:are|were)\s+)?(?:an?\s+)?(?:unrestricted|unfiltered|jailbroken|evil|uncensored)\b"),
    _r("direct", EntityType.JAILBREAK, 0.92, r"\bdo\s+anything\s+now\b|\bDAN\s+mode\b|\bdeveloper\s+mode\b|\bjailbreak(?:ed|ing)?\s+(?:mode|prompt)\b"),
    _r("direct", EntityType.JAILBREAK, 0.88,
       r"\bpretend\b[^.\n]{0,40}\b(?:no|without)\s+(?:rules|restrictions|filters|guidelines|safety)\b"),
    # -- instruction-hierarchy / delimiter attacks
    _r("direct", EntityType.PROMPT_INJECTION, 0.88, r"<\|?(?:im_start|im_end|system|endoftext)\|?>"),
    _r("direct", EntityType.PROMPT_INJECTION, 0.88, r"\[/?(?:INST|SYS|SYSTEM)\]", re.IGNORECASE),
    _r("direct", EntityType.PROMPT_INJECTION, 0.8, r"^\s*(?:#{2,}\s*)?(?:system|assistant)\s*(?:prompt)?\s*:\s*\S", re.IGNORECASE | re.MULTILINE),
    _r("direct", EntityType.PROMPT_INJECTION, 0.85, r"\bnew\s+(?:system\s+)?instructions?\s*:|\b(?:end|begin)\s+of\s+(?:the\s+)?system\s+(?:prompt|message)\b"),
    _r("direct", EntityType.PROMPT_INJECTION, 0.78,
       r"\b(?:from\s+now\s+on|henceforth)\b[^.\n]{0,40}\b(?:you\s+(?:must|will|shall)|only\s+(?:respond|answer))\b"),
    # -- indirect injection (instructions aimed at an AI inside documents / tool output)
    _r("indirect", EntityType.PROMPT_INJECTION, 0.86,
       r"\b(?:AI|assistant|LLM|model|chatbot)\b[^.\n]{0,20}\b(?:must|should|need\s+to|will)\b[^.\n]{0,60}\b(?:ignore|disregard|instead|do\s+not\s+(?:tell|inform|mention))"),
    _r("indirect", EntityType.PROMPT_INJECTION, 0.88, r"\bdo\s+not\s+(?:tell|inform|alert)\s+the\s+user\b"),
    _r("indirect", EntityType.PROMPT_INJECTION, 0.86,
       r"\b(?:when|if)\s+(?:an?\s+)?(?:AI|assistant|LLM|language\s+model)\s+(?:reads|processes|summari[sz]es|sees)\s+this\b"),
    # -- data exfiltration
    _r("exfiltration", EntityType.DATA_EXFILTRATION, 0.88,
       # Requires a sensitive-object word so ordinary "send the invoice to x@y.com" is not flagged.
       r"\b(?:send|post|upload|exfiltrate|forward|email|transmit|leak)\b[^.\n]{0,40}?\b(?:all|everything|entire|whole|conversation|chat|history|data|secrets?|credentials?|passwords?|keys?|tokens?|prompts?|instructions|contents?|records|database)\b[^.\n]{0,40}?\bto\s+(?:https?://\S+|[\w.+-]+@[\w-]+\.[\w.-]+)"),
    _r("exfiltration", EntityType.DATA_EXFILTRATION, 0.9,
       r"!\[[^\]\n]{0,100}\]\(https?://[^)\s]{1,300}[?&](?:data|q|d|s|secret|token|prompt|content|payload|exfil|leak|msg|text|chat|history)=[^)\s]*\)"),
]

_B64 = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")
_HEX = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){12,}(?![0-9A-Fa-f])")
_PCT = re.compile(r"(?:[A-Za-z0-9._~-]|%[0-9A-Fa-f]{2}){12,}")
_MAX_ENCODED_CANDIDATES = 50


def normalize_with_map(text: str) -> tuple[str, list[int]]:
    """Normalize for matching and return, for each output char, its index in the original text."""
    out: list[str] = []
    idx: list[int] = []
    for i, ch in enumerate(text):
        if ord(ch) in _ZERO_WIDTH:
            continue
        for c in unicodedata.normalize("NFKD", ch):
            if unicodedata.category(c) in ("Mn", "Cf"):
                continue
            out.append(c.translate(_HOMOGLYPHS) if ord(c) in _HOMOGLYPHS else c)
            idx.append(i)
    return "".join(out), idx


def _collapse_spaced(norm: str, idx: list[int]) -> tuple[str, list[int]]:
    out: list[str] = []
    omap: list[int] = []
    pos = 0
    for m in _SPACED_RUN.finditer(norm):
        out.append(norm[pos:m.start()])
        omap.extend(idx[pos:m.start()])
        for j in range(m.start(), m.end()):
            if norm[j].isalpha():
                out.append(norm[j])
                omap.append(idx[j])
        pos = m.end()
    out.append(norm[pos:])
    omap.extend(idx[pos:])
    return "".join(out), omap


def _printable_ratio(b: bytes) -> float:
    return sum(32 <= c < 127 or c in (9, 10, 13) for c in b) / len(b) if b else 0.0


class PromptInjectionDetector(Detector):
    name = "prompt_injection"
    version = "1.0.0"

    def detect(self, text: str) -> list[Detection]:
        best: dict[tuple[EntityType, int, int], Detection] = {}

        def add(rule: _Rule, layer: str, orig_start: int, orig_end: int, conf: float) -> None:
            key = (rule.entity, orig_start, orig_end)
            det = make_detection(rule.entity, text[orig_start:orig_end], orig_start, orig_end, conf,
                                 rule.severity, f"{self.name}.{layer}", self.version)
            if key not in best or best[key].confidence < det.confidence:
                best[key] = det

        def run_variant(variant: str, idx: list[int], layer: str, penalty: float) -> None:
            for rule in _RULES:
                for m in rule.regex.finditer(variant):
                    if m.end() == m.start():
                        continue
                    a, b = idx[m.start()], idx[m.end() - 1]
                    add(rule, layer if layer != "direct" else rule.sub, min(a, b), max(a, b) + 1,
                        rule.confidence - penalty)

        identity = list(range(len(text)))
        run_variant(text, identity, "direct", 0.0)

        norm, nidx = normalize_with_map(text)
        if norm != text:
            run_variant(norm, nidx, "obfuscated", 0.03)
        if re.search(r"[A-Za-z][013457@$!][A-Za-z]", norm):
            run_variant(norm.translate(_LEET), nidx, "obfuscated", 0.06)
        collapsed, cidx = _collapse_spaced(norm, nidx)
        if collapsed != norm:
            run_variant(collapsed, cidx, "obfuscated", 0.04)
        if len(norm) <= 100_000:  # reversal / ROT13 are whole-text passes; bound their cost
            run_variant(norm[::-1], list(reversed(nidx)), "obfuscated", 0.08)
            run_variant(codecs.encode(norm, "rot_13"), nidx, "obfuscated", 0.08)

        self._scan_encoded(text, best)
        return sorted(best.values(), key=lambda d: (d.location.start, d.location.end))

    def _scan_encoded(self, text: str, best: dict[tuple[EntityType, int, int], Detection]) -> None:
        candidates: list[tuple[int, int, bytes]] = []
        for m in _B64.finditer(text):
            token = m.group(0)
            try:
                decoded = base64.b64decode(token + "=" * (-len(token) % 4), validate=True)
            except (binascii.Error, ValueError):
                continue
            candidates.append((m.start(), m.end(), decoded))
        for m in _HEX.finditer(text):
            try:
                candidates.append((m.start(), m.end(), bytes.fromhex(m.group(0))))
            except ValueError:
                continue
        for m in _PCT.finditer(text):
            if m.group(0).count("%") < 3:
                continue
            candidates.append((m.start(), m.end(), unquote(m.group(0)).encode("utf-8", "ignore")))

        for start, end, raw in candidates[:_MAX_ENCODED_CANDIDATES]:
            if _printable_ratio(raw) < 0.85:
                continue
            decoded_text, _ = normalize_with_map(raw.decode("utf-8", "ignore"))
            for rule in _RULES:
                if rule.regex.search(decoded_text):
                    key = (rule.entity, start, end)
                    det = make_detection(rule.entity, text[start:end], start, end, rule.confidence - 0.05,
                                         rule.severity, f"{self.name}.encoded", self.version)
                    if key not in best or best[key].confidence < det.confidence:
                        best[key] = det
