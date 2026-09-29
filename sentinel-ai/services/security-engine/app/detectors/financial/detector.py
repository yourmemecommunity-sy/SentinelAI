"""Financial identifier detectors: credit card (Luhn), bank account, IBAN, UPI, IFSC."""
from __future__ import annotations

import re

from app.detectors.base import PatternDetector, PatternSpec, rx
from app.models.types import EntityType, Severity
from app.utils.checksums import iban_valid, luhn_valid

_CTX = re.IGNORECASE

# Card networks by issuer prefix AND the lengths that network actually issues. Luhn alone is not enough: other
# identifiers use the same checksum - notably IMEI device numbers (15 digits, Luhn check digit), which a prefix-only rule
# reported as cards. A 15-digit number is now only a card if it is Amex (34/37) or in a Maestro range.
_CARD_NETWORKS: tuple[tuple[re.Pattern[str], frozenset[int]], ...] = (
    (re.compile(r"^4"), frozenset({13, 16, 19})),                                                      # Visa
    (re.compile(r"^(?:5[1-5]|222[1-9]|22[3-9]\d|2[3-6]\d\d|27[01]\d|2720)"), frozenset({16})),       # Mastercard
    (re.compile(r"^3[47]"), frozenset({15})),                                                          # American Express
    (re.compile(r"^(?:30[0-5]|3095|36|3[89])"), frozenset({14, 16, 17, 18, 19})),                     # Diners Club
    (re.compile(r"^35(?:2[89]|[3-8]\d)"), frozenset({16, 17, 18, 19})),                               # JCB
    (re.compile(r"^(?:6011|64[4-9]|65)"), frozenset({16, 17, 18, 19})),                               # Discover
    (re.compile(r"^62"), frozenset({16, 17, 18, 19})),                                                 # UnionPay
    (re.compile(r"^(?:5[06-9]|6\d)"), frozenset(range(13, 20))),                                      # Maestro
    (re.compile(r"^(?:60|65|81|82|508|353|356)"), frozenset({16})),                                   # RuPay
)
# Text right before the number that says it is a device identifier, not a card.
_DEVICE_ID_CONTEXT = re.compile(r"\bimei\b|\bimeisv\b|\bmeid\b|device\s+(?:id|identifier|serial)|serial\s+(?:no|number)", _CTX)


def _card_network_ok(digits: str) -> bool:
    return any(prefix.match(digits) and len(digits) in lengths for prefix, lengths in _CARD_NETWORKS)


def _card_check(value: str, ctx: str) -> float | None:
    digits = re.sub(r"\D", "", value)
    if not luhn_valid(digits) or not _card_network_ok(digits):
        return None
    if len(set(digits)) == 1:  # 0000..., 1111... are not real PANs
        return None
    if _DEVICE_ID_CONTEXT.search(ctx[-40:]):  # "IMEI: 35..." - a Luhn-valid device number, not a payment card
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
