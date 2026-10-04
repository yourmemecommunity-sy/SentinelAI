"""Explainable, replayable decisions.

Every scan result carries an `Explanation`: which detectors fired, which tier decided, the classifier score and band,
the judge's verdict, the policy rule (or baseline) that set the action, and the versions of everything that took part.
It holds NO content: the input is represented by a keyed HMAC (`content_hmac`), so an event can later be replayed by
someone who has the original text, while the stored event alone reveals nothing about it.

The judge's free-text `reason` is returned to the caller but is marked transient: it is model prose about the (masked)
text and could echo parts of it, so the gateway never stores it (zero-content audit design).
"""
from __future__ import annotations

import hashlib
import hmac
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from app.models.types import Action, EntityType

DecidedBy = Literal["rules", "classifier", "judge", "fail_closed"]
Band = Literal["attack", "uncertain", "benign"]
PolicySource = Literal["policy_rule", "baseline", "risk_escalation", "no_detection", "fail_closed"]


class FiredDetector(BaseModel):
    model_config = ConfigDict(extra="forbid")
    detector: str
    entity: EntityType
    count: int
    max_confidence: float
    tier: int


class ClassifierInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")
    model: str
    score: float
    threshold: float          # decision threshold when the judge is not used
    band_low: float | None    # judge band (only when the judge is usable)
    band_high: float | None
    band: Band
    windows_scored: int = 1
    windows_total: int = 1   # > windows_scored: only the start and end of a long text were classified (see cascade)


class JudgeInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")
    called: bool
    cached: bool = False
    skipped_reason: str | None = None   # "disabled_by_policy" | "not_configured" | "outside_band" | "replayed"
    verdict: Literal["attack", "benign"] | None = None
    category: str | None = None
    confidence: float | None = None
    reason: str | None = Field(default=None, description="transient; never persisted")
    model: str | None = None
    prompt_version: str | None = None
    latency_ms: float | None = None


class PolicyInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")
    policy_id: str
    policy_version: int
    deciding_entity: EntityType | None
    deciding_action: Action
    source: PolicySource


class Explanation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    decided_by: DecidedBy
    tier: int = Field(ge=1, le=3)
    detectors_fired: list[FiredDetector]
    classifier: ClassifierInfo | None = None
    judge: JudgeInfo | None = None
    policy: PolicyInfo
    versions: dict[str, str]
    content_hmac: str

    def storable(self) -> "Explanation":
        """Copy without transient fields (the judge's free-text reason)."""
        if self.judge is None or self.judge.reason is None:
            return self
        return self.model_copy(update={"judge": self.judge.model_copy(update={"reason": None})})


def content_hmac(key: bytes, text: str) -> str:
    """Keyed hash of the scanned text (domain-separated from value digests). Never reversible without the text."""
    return hmac.new(key, b"content:" + text.encode("utf8", "surrogatepass"), hashlib.sha256).hexdigest()
