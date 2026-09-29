"""PII detectors: email, phone, address, date of birth, PAN, Aadhaar-like, passport, SSN, driver licence.

Free-text person names and places are found by the NER layer (app/detectors/ner), not here.
The SSN-context and date-of-birth rules below were tuned on the ai4privacy TRAIN split only
(docs/verification/11-pii-improvement-cycle.md); the held-out validation split was not used.
"""
from __future__ import annotations

import re

from app.detectors.base import PatternDetector, PatternSpec, rx
from app.models.types import Detection, EntityType, Severity
from app.utils.checksums import verhoeff_valid

_CTX = re.IGNORECASE


def _digits(value: str) -> str:
    return re.sub(r"\D", "", value)


def _phone_check(value: str, _ctx: str) -> float | None:
    n = len(_digits(value))
    return 0.9 if 8 <= n <= 15 else None


def _aadhaar_check(value: str, ctx: str) -> float | None:
    digits = _digits(value)
    if len(digits) != 12:
        return None
    if verhoeff_valid(digits):
        return 0.95
    # Checksum fails: only report when the text itself says this is an Aadhaar number.
    return 0.7 if re.search(r"aadhaa?r|\buid\b", ctx, _CTX) else None


def _india_mobile_check(value: str, ctx: str) -> float | None:
    return 0.9 if re.search(r"phone|mobile|call|contact|whatsapp|tel\b", ctx, _CTX) else 0.7


# Words that say the number that follows is a social-security / social-insurance / national-insurance number.
_SSN_CONTEXT = rx(r"\bssn\b|social[\s_-]*security|social[\s_-]*(?:insurance[\s_-]*)?(?:number|no\b|num\b|#)|"
                  r"socialsecuritynumber|\bsin\b|national[\s_-]*insurance|\bni[\s_-]*(?:number|no\b)", _CTX)


def _ssn_context_check(value: str, _ctx: str) -> float | None:
    # 9-13 digits covers US SSNs (9), Canadian SINs (9) and other national social numbers written with separators.
    return 0.9 if 9 <= len(_digits(value)) <= 13 else None


_MONTH = (r"(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|June?|July?|Aug(?:ust)?|Sept?(?:ember)?|"
          r"Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)")
_DOB_CONTEXT = rx(r"\bdob\b|d\.o\.b|date[\s_-]*of[\s_-]*birth|dateofbirth|\bborn\b|birth[\s_-]*date|birthdate|"
                  r"birthday|\bbirth\b", _CTX)


_SPECS = [
    PatternSpec(
        EntityType.EMAIL,
        rx(r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){0,8}\.[A-Za-z]{2,24}(?![A-Za-z0-9-])"),
        Severity.MEDIUM, 0.95),
    # International: +CC then 7-14 digits with common separators.
    PatternSpec(EntityType.PHONE, rx(r"(?<![\w+])\+\d{1,3}[\s.-]?(?:\(\d{1,4}\)[\s.-]?)?\d{1,4}(?:[\s.-]?\d{2,4}){2,4}(?!\d)"),
                Severity.MEDIUM, 0.9, check=_phone_check),
    # North-American style with mandatory separators (avoids matching bare digit runs).
    PatternSpec(EntityType.PHONE, rx(r"(?<![\w+])\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}(?!\d)"),
                Severity.MEDIUM, 0.85),
    # Indian 10-digit mobile numbers.
    PatternSpec(EntityType.PHONE, rx(r"(?<![\d.])[6-9]\d{9}(?![\d.])"),
                Severity.MEDIUM, 0.7, check=_india_mobile_check),
    PatternSpec(EntityType.PAN, rx(r"\b[A-Z]{3}[ABCFGHJKLPT][A-Z][0-9]{4}[A-Z]\b"), Severity.HIGH, 0.9),
    PatternSpec(EntityType.AADHAAR, rx(r"(?<![\d-])[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}(?![\d-])"),
                Severity.HIGH, 0.95, check=_aadhaar_check, context_window=40),
    PatternSpec(EntityType.PASSPORT, rx(r"\b[A-Z]{1,2}\d{6,8}\b"), Severity.HIGH, 0.85,
                context=rx(r"passport", _CTX), context_window=40),
    PatternSpec(EntityType.SSN, rx(r"(?<![\d-])(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?![\d-])"),
                Severity.HIGH, 0.92),
    PatternSpec(EntityType.SSN, rx(r"(?<!\d)\d{9}(?!\d)"), Severity.HIGH, 0.8,
                context=rx(r"\bssn\b|social security", _CTX), context_window=40),
    # Any 9-13 digit number written with spaces, dots or dashes right after "social security number", "social number",
    # "SIN", "national insurance"...: phone-shaped SSNs were otherwise only caught as PHONE (or not at all).
    PatternSpec(EntityType.SSN, rx(r"(?<![\w.-])\d[\d .-]{7,16}\d(?![\w-])"), Severity.HIGH, 0.9,
                context=_SSN_CONTEXT, context_window=40, check=_ssn_context_check),
    PatternSpec(EntityType.DRIVER_LICENSE, rx(r"\b(?=[A-Z0-9-]*\d)[A-Z0-9][A-Z0-9-]{5,19}\b"), Severity.HIGH, 0.8,
                context=rx(r"driver'?s?[\s_-]*licen[sc]e|\bDL\b\s*(?:no|number|#)?", _CTX), context_window=40),
    PatternSpec(EntityType.DATE_OF_BIRTH,
                rx(r"\b(?:\d{1,2}[/.-]\d{1,2}[/.-]\d{2,4}|\d{4}-\d{2}-\d{2}|\d{1,2}(?:st|nd|rd|th)?\s+[A-Za-z]{3,9},?\s+\d{4})\b"),
                Severity.MEDIUM, 0.85,
                context=rx(r"\bdob\b|date\s+of\s+birth|born\s+on|birth\s*date|birthday", _CTX), context_window=30),
    # Wider net, still only after a birth-related word (within 60 characters, e.g. across "Date of birth: <strong>"):
    # ISO date-times, "May 5th, 1966", "January/88", "5th of May 1966" and all-numeric dates.
    PatternSpec(EntityType.DATE_OF_BIRTH,
                rx(r"\b(?:\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}(?::\d{2})?)?|\d{1,2}[/.-]\d{1,2}[/.-]\d{2,4}|"
                   rf"{_MONTH}\.?\s+\d{{1,2}}(?:st|nd|rd|th)?,?\s+\d{{4}}|{_MONTH}\s*/\s*\d{{2,4}}|"
                   rf"\d{{1,2}}(?:st|nd|rd|th)?\s+(?:of\s+)?{_MONTH}\.?,?\s+\d{{4}})(?![\w:])", _CTX),
                Severity.MEDIUM, 0.8, context=_DOB_CONTEXT, context_window=60),
    PatternSpec(EntityType.ADDRESS,
                rx(r"\b\d{1,5}\s+(?:[A-Z][A-Za-z]+\s){1,3}(?:Street|St|Road|Rd|Avenue|Ave|Lane|Ln|Boulevard|Blvd|Drive|Dr|Nagar|Marg)\b\.?"),
                Severity.MEDIUM, 0.6),
]


class PiiDetector(PatternDetector):
    """Pattern detector plus one disambiguation rule: a number reported as an SSN (only possible with SSN wording in
    front of it, or in SSN format) is not ALSO reported as a phone number. Both would be masked, but the audit label,
    the per-type policy and the masking format would otherwise be the phone's."""

    def detect(self, text: str) -> list[Detection]:
        found = super().detect(text)
        ssn = [(d.location.start, d.location.end) for d in found if d.entity is EntityType.SSN]
        if not ssn:
            return found
        return [d for d in found if not (d.entity is EntityType.PHONE and
                                         any(s <= d.location.start and d.location.end <= e for s, e in ssn))]


def build_pii_detector() -> PatternDetector:
    return PiiDetector("pii", _SPECS, version="1.1.0")
