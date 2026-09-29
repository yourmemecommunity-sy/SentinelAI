"""Detector registry. Custom detectors are added with `register`; the default bundle covers all built-ins."""
from __future__ import annotations

from app.config.settings import Settings
from app.detectors.base import Detector
from app.detectors.confidential_data import build_confidential_detector
from app.detectors.credentials import build_credential_detector
from app.detectors.financial import build_financial_detector
from app.detectors.ner import NerDetector
from app.detectors.pii import build_pii_detector
from app.detectors.prompt_injection import PromptInjectionDetector
from app.detectors.secrets import build_secret_detectors


class DetectorRegistry:
    def __init__(self, detectors: list[Detector] | None = None) -> None:
        self._detectors: list[Detector] = list(detectors or [])

    def register(self, detector: Detector) -> None:
        if any(d.name == detector.name for d in self._detectors):
            raise ValueError(f"detector already registered: {detector.name}")
        self._detectors.append(detector)

    @property
    def detectors(self) -> tuple[Detector, ...]:
        return tuple(self._detectors)

    def __len__(self) -> int:
        return len(self._detectors)


def default_registry(settings: Settings | None = None) -> DetectorRegistry:
    s = settings or Settings()
    reg = DetectorRegistry()
    for det in (build_pii_detector(), build_financial_detector(), *build_secret_detectors(),
                build_credential_detector(), PromptInjectionDetector(), build_confidential_detector()):
        reg.register(det)
    if s.ner_enabled:
        reg.register(NerDetector(s.ner_model))
    return reg
