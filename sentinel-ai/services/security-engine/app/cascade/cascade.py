"""The detection cascade after Tier 1 (rules + NER):

    Tier 2  local classifier scores the input (CPU, nothing leaves the process)
            score >= band_high -> attack          score < band_low -> benign
    Tier 3  only inside [band_low, band_high), and only if the judge is configured AND the organisation allows it:
            the judge sees the SANITIZED text and decides.
            Without a usable judge, the classifier decides alone at `threshold`.

Thresholds and the band are chosen on training splits only (docs/verification/12-ai-vs-ai.md). Every failure of a tier
raises; the pipeline turns it into a fail-closed BLOCK.
"""
from __future__ import annotations

import time
from dataclasses import dataclass

from app.cascade.classifier import InjectionClassifier
from app.cascade.judge import CachedJudge, Judge, JudgeError, RecordedJudge
from app.models.explanation import Band, ClassifierInfo, JudgeInfo
from app.models.types import EntityType

_CATEGORY_ENTITY = {"jailbreak": EntityType.JAILBREAK, "data_exfiltration": EntityType.DATA_EXFILTRATION}


@dataclass(frozen=True)
class CascadeConfig:
    threshold: float          # classifier alone
    band_low: float           # judge band [band_low, band_high)
    band_high: float
    judge_min_confidence: float = 0.5

    def __post_init__(self) -> None:
        if not (0.0 <= self.band_low <= self.band_high <= 1.0 and 0.0 <= self.threshold <= 1.0):
            raise ValueError("cascade thresholds must satisfy 0 <= band_low <= band_high <= 1")


@dataclass(frozen=True)
class CascadeOutcome:
    attack: bool
    tier: int                       # 2 = classifier decided, 3 = judge decided
    entity: EntityType | None
    confidence: float
    classifier: ClassifierInfo
    judge: JudgeInfo
    judge_elapsed_ms: float
    windows_scored: int = 1


class Cascade:
    def __init__(self, classifier: InjectionClassifier, judge: Judge | None, config: CascadeConfig) -> None:
        self.classifier = classifier
        self.judge = judge
        self.config = config

    def healthy(self) -> bool:
        return self.classifier.healthy()

    def evaluate(self, raw_text: str, sanitized_text: str, judge_allowed: bool,
                 judge_override: Judge | None = None, force_no_judge: bool = False) -> CascadeOutcome:
        """`raw_text` goes only to the local classifier; `sanitized_text` is the only thing the judge may receive.

        Replay uses `judge_override` (a RecordedJudge that answers with the recorded verdict instead of calling the API)
        and `force_no_judge` (the judge was not usable when the event was recorded)."""
        cfg = self.config
        detail = self.classifier.score_detail(raw_text)
        score = detail.score
        judge = judge_override if judge_override is not None else self.judge
        skip = ("not_configured" if judge is None or force_no_judge
                else "disabled_by_policy" if not judge_allowed else None)
        judge_usable = skip is None
        band: Band
        if judge_usable:
            band = "attack" if score >= cfg.band_high else "benign" if score < cfg.band_low else "uncertain"
            if detail.partial and band == "benign":
                band = "uncertain"  # the middle of a long text was not classified: let the judge look at it
        else:
            band = "attack" if score >= cfg.threshold else "benign"
        info = ClassifierInfo(model=self.classifier.version, score=round(score, 5), threshold=cfg.threshold,
                              band_low=cfg.band_low if judge_usable else None,
                              band_high=cfg.band_high if judge_usable else None, band=band,
                              windows_scored=detail.windows_scored, windows_total=detail.windows_total)
        if band != "uncertain":
            judge_info = JudgeInfo(called=False, skipped_reason=skip or "outside_band")
            return CascadeOutcome(attack=band == "attack", tier=2,
                                  entity=EntityType.PROMPT_INJECTION if band == "attack" else None,
                                  confidence=score, classifier=info, judge=judge_info, judge_elapsed_ms=0.0,
                                  windows_scored=detail.windows_scored)

        if judge is None:  # unreachable: judge_usable implies a judge; kept explicit instead of an assert
            raise JudgeError("judge_not_configured")
        started = time.perf_counter()
        cached = False
        replayed = isinstance(judge, RecordedJudge)
        if isinstance(judge, CachedJudge):
            hit = judge.lookup(sanitized_text)
            cached = hit is not None
            verdict = hit if hit is not None else judge.judge(sanitized_text)
        else:
            verdict = judge.judge(sanitized_text)
        elapsed = (time.perf_counter() - started) * 1000
        attack = verdict.verdict == "attack" and verdict.confidence >= cfg.judge_min_confidence
        judge_info = JudgeInfo(
            called=not replayed and not cached, cached=cached, skipped_reason="replayed" if replayed else None,
            verdict=verdict.verdict, category=verdict.category, confidence=verdict.confidence, reason=verdict.reason,
            model=judge.model, prompt_version=judge.prompt_version, latency_ms=round(elapsed, 1))
        entity = _CATEGORY_ENTITY.get(verdict.category, EntityType.PROMPT_INJECTION) if attack else None
        return CascadeOutcome(attack=attack, tier=3, entity=entity, confidence=verdict.confidence, classifier=info,
                              judge=judge_info, judge_elapsed_ms=elapsed, windows_scored=detail.windows_scored)
