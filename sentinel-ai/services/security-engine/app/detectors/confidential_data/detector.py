"""Business-data detectors: internal URLs, confidentiality markers, and organization-supplied terms.

Not implemented here (need an ML classifier, see roadmap): proprietary source code, internal
architecture descriptions, contracts, and pricing information.
"""
from __future__ import annotations

import re
from collections.abc import Mapping

from app.detectors.base import Detector, PatternDetector, PatternSpec, make_detection, rx
from app.models.types import Detection, EntityType, Severity

_CTX = re.IGNORECASE

_SPECS = [
    PatternSpec(EntityType.INTERNAL_URL,
                rx(r"\bhttps?://(?:[A-Za-z0-9-]{1,63}\.){1,6}(?:internal|corp|local|lan|intranet|private)\b(?::\d+)?[^\s]{0,200}", _CTX),
                Severity.MEDIUM, 0.9),
    PatternSpec(EntityType.INTERNAL_URL,
                rx(r"\bhttps?://(?:localhost|127\.0\.0\.1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b(?::\d+)?[^\s]{0,200}", _CTX),
                Severity.MEDIUM, 0.85),
    PatternSpec(EntityType.CONFIDENTIAL_MARKER,
                rx(r"\b(?:strictly\s+confidential|confidential\s*(?:&|and)?\s*proprietary|internal\s+use\s+only|do\s+not\s+(?:distribute|share|forward)|company\s+confidential)\b", _CTX),
                Severity.LOW, 0.8),
]


class CustomTermDetector(Detector):
    """Organization-defined confidential terms (project code names, customer names, ...).

    `terms` maps term -> severity name. Matching is case-insensitive on word boundaries.
    """

    name = "confidential.custom_terms"
    version = "1.0.0"

    def __init__(self, terms: Mapping[str, Severity]) -> None:
        self._severity = {t.lower(): s for t, s in terms.items() if t.strip()}
        self._rx = (re.compile(r"\b(?:" + "|".join(re.escape(t) for t in sorted(self._severity, key=len, reverse=True)) + r")\b",
                               re.IGNORECASE) if self._severity else None)

    def detect(self, text: str) -> list[Detection]:
        if self._rx is None:
            return []
        return [make_detection(EntityType.CUSTOM_CONFIDENTIAL, m.group(0), m.start(), m.end(), 0.95,
                               self._severity[m.group(0).lower()], self.name, self.version)
                for m in self._rx.finditer(text)]


def build_confidential_detector() -> PatternDetector:
    return PatternDetector("confidential", _SPECS, version="1.0.0")
