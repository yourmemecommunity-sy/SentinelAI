"""Shared helpers for the cascade tests (tests/cascade/)."""
from typing import Protocol

from app.cascade.cascade import Cascade, CascadeConfig
from app.cascade.classifier import StaticClassifier
from app.cascade.judge import FakeJudge, JudgeVerdict
from app.config.settings import Settings
from app.models.explanation import ClassifierInfo, Explanation, JudgeInfo
from app.detectors.registry import DetectorRegistry
from app.pipelines import ScanPipeline

CONFIG = CascadeConfig(threshold=0.5, band_low=0.2, band_high=0.9)


def verdict(v: str = "attack", category: str = "direct_injection", confidence: float = 0.9) -> JudgeVerdict:
    return JudgeVerdict(verdict=v, category=category, confidence=confidence, reason="test")  # type: ignore[arg-type]


class _Explained(Protocol):
    @property
    def explanation(self) -> Explanation | None: ...


def explain(result: _Explained) -> Explanation:
    assert result.explanation is not None, "every scan result must carry an explanation"
    return result.explanation


def classifier_of(e: Explanation) -> ClassifierInfo:
    assert e.classifier is not None, "the classifier should have run for this test"
    return e.classifier


def judge_of(e: Explanation) -> JudgeInfo:
    assert e.judge is not None, "the judge decision should have been recorded for this test"
    return e.judge


def make_pipeline(registry: DetectorRegistry, score: float | dict[str, float] = 0.5, judge: FakeJudge | None = None,
                  with_judge: bool = True) -> tuple[ScanPipeline, StaticClassifier, FakeJudge]:
    """With with_judge=False the returned judge is not wired in (so it must never be called)."""
    clf = StaticClassifier(score)
    j = judge or FakeJudge(verdict())
    return ScanPipeline(registry, Settings(), Cascade(clf, j if with_judge else None, CONFIG)), clf, j
