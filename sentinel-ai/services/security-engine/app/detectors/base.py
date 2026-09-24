"""Detector contract and the shared pattern-matching implementation.

Every detector returns structured evidence (`Detection`) and never the matched value.
Regexes here MUST be free of nested/ambiguous quantifiers: Python's `re` cannot be interrupted, so
linear-time patterns plus the pipeline's input-size cap are the ReDoS defence.
"""
from __future__ import annotations

import re
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass

from app.models.types import Detection, EntityType, Location, Severity
from app.utils.hashing import value_digest

# check(value, preceding_context) -> confidence to use, or None to reject the candidate.
CheckFn = Callable[[str, str], "float | None"]


class Detector(ABC):
    """Extension point: implement and register via `DetectorRegistry` to add custom detectors."""

    name: str
    version: str = "1.0.0"

    @abstractmethod
    def detect(self, text: str) -> list[Detection]:
        ...


def make_detection(entity: EntityType, value: str, start: int, end: int, confidence: float,
                   severity: Severity, detector: str, version: str) -> Detection:
    return Detection(
        entity=entity, confidence=round(min(max(confidence, 0.0), 1.0), 4), severity=severity,
        location=Location(start=start, end=end), detector=detector, detector_version=version,
        value_digest=value_digest(entity.value, value),
    )


@dataclass(frozen=True)
class PatternSpec:
    entity: EntityType
    regex: re.Pattern[str]
    severity: Severity
    confidence: float
    group: int = 0
    context: re.Pattern[str] | None = None  # must appear in the `context_window` chars before the match
    context_window: int = 48
    check: CheckFn | None = None


class PatternDetector(Detector):
    def __init__(self, name: str, specs: list[PatternSpec], version: str = "1.0.0") -> None:
        self.name = name
        self.version = version
        self._specs = specs

    def detect(self, text: str) -> list[Detection]:
        out: list[Detection] = []
        for spec in self._specs:
            for m in spec.regex.finditer(text):
                value = m.group(spec.group)
                if not value:
                    continue
                start, end = m.span(spec.group)
                before = text[max(0, start - spec.context_window):start]
                if spec.context is not None and not spec.context.search(before):
                    continue
                confidence = spec.confidence
                if spec.check is not None:
                    checked = spec.check(value, before)
                    if checked is None:
                        continue
                    confidence = checked
                out.append(make_detection(spec.entity, value, start, end, confidence,
                                          spec.severity, self.name, self.version))
        return out


def rx(pattern: str, flags: int = 0) -> re.Pattern[str]:
    return re.compile(pattern, flags)
