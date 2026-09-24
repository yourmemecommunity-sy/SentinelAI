"""Credential-in-context detectors: passwords, bearer tokens, connection strings with embedded credentials."""
from __future__ import annotations

import re

from app.detectors.base import PatternDetector, PatternSpec, rx
from app.models.types import EntityType, Severity

_CTX = re.IGNORECASE
_PLACEHOLDER = re.compile(r"^(?:\*+|x+|\.+|<[^>]*>|\{\{.*\}\}|\$\{?\w+\}?|%\w+%|your[_-]?password|password|changeme|example|null|none)$",
                          re.IGNORECASE)


def _password_check(value: str, _ctx: str) -> float | None:
    v = value.rstrip(".,;)")
    if len(v) < 4 or _PLACEHOLDER.match(v):
        return None
    return 0.9


def _bearer_check(value: str, _ctx: str) -> float | None:
    return None if _PLACEHOLDER.match(value) else 0.9


_SPECS = [
    PatternSpec(
        EntityType.PASSWORD,
        rx(r"\b(?:password|passwd|pwd|passphrase|db[_-]?pass(?:word)?|secret[_-]?key)\b[\"']?\s*(?:is\s*:?|[:=]|=>)\s*[\"']?([^\s\"']{4,128})", _CTX),
        Severity.CRITICAL, 0.9, group=1, check=_password_check),
    PatternSpec(EntityType.OAUTH_TOKEN, rx(r"\bBearer\s+([A-Za-z0-9._~+/-]{20,}=*)", _CTX),
                Severity.CRITICAL, 0.9, group=1, check=_bearer_check),
    PatternSpec(
        EntityType.CONNECTION_STRING,
        rx(r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?|mssql|sqlserver|oracle|jdbc:[a-z]{2,12})://[^\s:@/]{1,128}:[^\s@/]{1,256}@[^\s/'\"]{1,256}(?:/[^\s'\"]*)?", _CTX),
        Severity.CRITICAL, 0.97),
    PatternSpec(EntityType.CONNECTION_STRING,
                rx(r"\b(?:Server|Data Source|Host)=[^;\s]{1,128};[^\n]{0,200}?\b(?:Password|Pwd)=[^;\s]{1,128}", _CTX),
                Severity.CRITICAL, 0.93),
]


def build_credential_detector() -> PatternDetector:
    return PatternDetector("credentials", _SPECS, version="1.0.0")
