import pytest

from app.cascade.cascade import Cascade, CascadeConfig
from app.cascade.classifier import StaticClassifier
from app.cascade.judge import FakeJudge, JudgeVerdict
from app.config.settings import Settings
from app.detectors.registry import DetectorRegistry, default_registry
from app.pipelines import ScanPipeline

CONFIG = CascadeConfig(threshold=0.5, band_low=0.2, band_high=0.9)


@pytest.fixture(scope="session")
def registry() -> DetectorRegistry:
    return default_registry()  # real rules + real NER model, loaded once


def verdict(v: str = "attack", category: str = "direct_injection", confidence: float = 0.9) -> JudgeVerdict:
    return JudgeVerdict(verdict=v, category=category, confidence=confidence, reason="test")  # type: ignore[arg-type]


def make_pipeline(registry: DetectorRegistry, score: float | dict[str, float] = 0.5, judge: FakeJudge | None = None,
                  with_judge: bool = True) -> tuple[ScanPipeline, StaticClassifier, FakeJudge | None]:
    clf = StaticClassifier(score)
    j = (judge or FakeJudge(verdict())) if with_judge else None
    return ScanPipeline(registry, Settings(), Cascade(clf, j, CONFIG)), clf, j
