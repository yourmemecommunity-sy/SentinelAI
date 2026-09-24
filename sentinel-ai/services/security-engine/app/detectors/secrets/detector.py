"""Token-format secret detectors (cloud keys, VCS tokens, JWTs, private keys) plus entropy analysis.

Layered: format-specific patterns first (high confidence), then a generic entropy detector as a
safety net for secrets whose format we do not know.
"""
from __future__ import annotations

import base64
import binascii
import json
import re

from app.detectors.base import Detector, PatternDetector, PatternSpec, make_detection, rx
from app.models.types import Detection, EntityType, Severity
from app.utils.entropy import shannon_entropy

_CTX = re.IGNORECASE


def _b64url_json(segment: str) -> object | None:
    try:
        raw = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
        decoded: object = json.loads(raw)
        return decoded
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None


def _jwt_check(value: str, _ctx: str) -> float | None:
    header = _b64url_json(value.split(".")[0])
    return 0.98 if isinstance(header, dict) and ("alg" in header or "typ" in header) else 0.75


def _aws_secret_check(value: str, _ctx: str) -> float | None:
    return 0.95 if shannon_entropy(value) >= 3.6 and re.search(r"[A-Z]", value) and re.search(r"[a-z0-9]", value) else None


_SPECS = [
    PatternSpec(EntityType.AWS_CREDENTIAL, rx(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA)[0-9A-Z]{16}\b"),
                Severity.CRITICAL, 0.98),
    PatternSpec(EntityType.AWS_CREDENTIAL, rx(r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])"),
                Severity.CRITICAL, 0.95, check=_aws_secret_check,
                context=rx(r"aws|secret[_\s-]*access[_\s-]*key|secret[_\s-]*key", _CTX), context_window=70),
    PatternSpec(EntityType.GOOGLE_CREDENTIAL, rx(r"\bAIza[0-9A-Za-z_-]{35}\b"), Severity.CRITICAL, 0.97),
    PatternSpec(EntityType.GOOGLE_CREDENTIAL, rx(r'"type"\s*:\s*"service_account"'), Severity.CRITICAL, 0.9),
    PatternSpec(EntityType.OAUTH_TOKEN, rx(r"\bya29\.[0-9A-Za-z_-]{20,}"), Severity.CRITICAL, 0.95),
    PatternSpec(EntityType.GITHUB_TOKEN, rx(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b"),
                Severity.CRITICAL, 0.98),
    PatternSpec(EntityType.API_KEY, rx(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"), Severity.CRITICAL, 0.96),
    PatternSpec(EntityType.API_KEY, rx(r"\b[sr]k_live_[0-9a-zA-Z]{24,}\b"), Severity.CRITICAL, 0.97),
    PatternSpec(EntityType.API_KEY, rx(r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{32,}\b"), Severity.CRITICAL, 0.95),
    PatternSpec(EntityType.API_KEY, rx(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b"), Severity.CRITICAL, 0.97),
    PatternSpec(EntityType.API_KEY, rx(r"\b(?:api[_-]?key|apikey|x-api-key|api[_-]?secret|client[_-]?secret)\b[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9_\-./+]{16,})", _CTX),
                Severity.CRITICAL, 0.9, group=1),
    PatternSpec(EntityType.JWT, rx(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*"),
                Severity.CRITICAL, 0.98, check=_jwt_check),
    # Whole PEM block; if the END marker is missing (truncated paste) consume to end of text so the
    # key body can never survive sanitization.
    PatternSpec(EntityType.PRIVATE_KEY,
                rx(r"-----BEGIN (?:[A-Z0-9]+ ){0,3}PRIVATE KEY(?: BLOCK)?-----[\s\S]{0,16384}?(?:-----END (?:[A-Z0-9]+ ){0,3}PRIVATE KEY(?: BLOCK)?-----|\Z)"),
                Severity.CRITICAL, 0.99),
]


class EntropyDetector(Detector):
    """Safety net: long random-looking tokens near credential keywords (or very long ones anywhere)."""

    name = "secrets.entropy"
    version = "1.0.0"
    _TOKEN = re.compile(r"(?<![A-Za-z0-9_\-+/=])[A-Za-z0-9_\-+/=]{24,200}(?![A-Za-z0-9_\-+/=])")
    _KEYWORD = re.compile(r"key|secret|token|credential|auth|passw|pwd|bearer", re.IGNORECASE)
    _HEX_ONLY = re.compile(r"^[0-9a-fA-F]+$")

    def detect(self, text: str) -> list[Detection]:
        out: list[Detection] = []
        for m in self._TOKEN.finditer(text):
            token = m.group(0)
            classes = sum(bool(re.search(p, token)) for p in (r"[a-z]", r"[A-Z]", r"[0-9]"))
            if classes < 2:
                continue
            entropy = shannon_entropy(token)
            near_keyword = bool(self._KEYWORD.search(text[max(0, m.start() - 40):m.start()]))
            if self._HEX_ONLY.match(token) and not near_keyword:
                continue  # commit hashes / checksums
            if near_keyword and entropy >= 3.8:
                confidence = 0.75
            elif len(token) >= 40 and entropy >= 4.5:
                confidence = 0.55
            else:
                continue
            out.append(make_detection(EntityType.HIGH_ENTROPY_SECRET, token, m.start(), m.end(), confidence,
                                      Severity.MEDIUM, self.name, self.version))
        return out


def build_secret_detectors() -> list[Detector]:
    return [PatternDetector("secrets", _SPECS, version="1.0.0"), EntropyDetector()]
