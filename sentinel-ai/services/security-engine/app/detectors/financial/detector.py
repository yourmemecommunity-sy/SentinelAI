"""Financial identifier detectors: credit card (Luhn), bank account, IBAN, UPI, IFSC."""
from __future__ import annotations

import re

from app.detectors.base import PatternDetector, PatternSpec, rx
from app.models.types import EntityType, Severity
from app.utils.checksums import iban_valid, luhn_valid

_CTX = re.IGNORECASE
# Major networks + Maestro/UnionPay/etc: first digit 3-6, or Mastercard 2-series. Luhn does the heavy lifting.
_CARD_PREFIX = re.compile(r"^(?:2[2-7]|[3-6])")


def _card_check(value: str, _ctx: str) -> float | None:
    digits = re.sub(r"\D", "", value)
    if not luhn_valid(digits) or not _CARD_PREFIX.match(digits):
        return None
    if len(set(digits)) == 1:  # 0000..., 1111... are not real PANs
        return None
    return 0.97


def _iban_check(value: str, _ctx: str) -> float | None:
    return 0.95 if iban_valid(value) else None


_UPI_HANDLES = (
    "okaxis|okhdfcbank|okicici|oksbi|ybl|ibl|axl|paytm|upi|apl|axisbank|hdfcbank|icici|sbi|"
    "postbank|pnb|boi|cnrb|kotak|indus|federal|yesbank|idfcbank|barodampay|airtel|jio|freecharge"
)

_SPECS = [
    PatternSpec(EntityType.CREDIT_CARD, rx(r"(?<![\d-])\d(?:[ -]?\d){12,18}(?![\d-])"),
                Severity.CRITICAL, 0.97, check=_card_check),
    PatternSpec(EntityType.BANK_ACCOUNT, rx(r"(?<!\d)\d{8,18}(?!\d)"), Severity.HIGH, 0.85,
                context=rx(r"a/?c\b|acct|account\s*(?:no|num|number|#)?|bank\s+account", _CTX), context_window=40),
    PatternSpec(EntityType.BANK_ACCOUNT, rx(r"\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]{4}){2,7}(?:\s?[A-Z0-9]{1,4})?\b"),
                Severity.HIGH, 0.95, check=_iban_check),
    PatternSpec(EntityType.UPI, rx(rf"(?<![A-Za-z0-9._-])[A-Za-z0-9._-]{{2,64}}@(?:{_UPI_HANDLES})(?![A-Za-z0-9.-])", _CTX),
                Severity.HIGH, 0.92),
    PatternSpec(EntityType.IFSC, rx(r"\b[A-Z]{4}0[A-Z0-9]{6}\b"), Severity.MEDIUM, 0.7),
    PatternSpec(EntityType.IFSC, rx(r"\b[A-Z]{4}0[A-Z0-9]{6}\b"), Severity.MEDIUM, 0.95,
                context=rx(r"ifsc", _CTX), context_window=30),
]


def build_financial_detector() -> PatternDetector:
    return PatternDetector("financial", _SPECS, version="1.0.0")
