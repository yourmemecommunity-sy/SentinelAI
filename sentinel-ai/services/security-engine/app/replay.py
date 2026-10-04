"""Replay a recorded decision: given the ORIGINAL input and the event's stored explanation, re-run the engine and report
whether the decision is identical, and which versions differ.

* The stored event holds no content, only a keyed hash; the caller must supply the original text, and the replay refuses
  to run if it does not match the recorded hash (so a replay can never be used to test other text against an event).
* The judge is not called again by default: its recorded verdict is reused (free and deterministic). If the replay now
  needs a verdict the event does not have, that is reported as a difference. `live_judge=true` asks the judge again.
* Nothing is written: no token vault, no audit event (the gateway records the replay request itself in the audit log).
"""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from app.cascade.judge import JudgeVerdict, RecordedJudge
from app.models.explanation import Explanation, content_hmac
from app.models.scan import ScanRequest
from app.models.types import Action, Direction, RequestContext
from app.pipelines import ScanPipeline
from app.policies.policy import Policy
from app.sanitization import InMemoryTokenVault
from app.utils.hashing import content_key


class RecordedDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")
    decision: Action
    explanation: Explanation


class ReplayRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    text: str
    organization_id: str = Field(min_length=1, max_length=128)
    direction: Direction = Direction.INPUT
    context: RequestContext = Field(default_factory=RequestContext)
    policy: Policy | None = None
    recorded: RecordedDecision
    live_judge: bool = False


class VersionDiff(BaseModel):
    name: str
    recorded: str | None
    current: str | None
    same: bool


class ReplayResult(BaseModel):
    content_matches: bool
    identical: bool
    recorded_decision: Action
    replayed_decision: Action | None
    recorded_decided_by: str
    replayed_decided_by: str | None
    differences: list[str]
    versions: list[VersionDiff]
    versions_identical: bool
    judge_source: str  # "recorded" | "live" | "not_needed"
    explanation: Explanation | None


def _recorded_verdict(expl: Explanation) -> JudgeVerdict | None:
    j = expl.judge
    if j is None or j.verdict is None or j.category is None or j.confidence is None:
        return None
    return JudgeVerdict(verdict=j.verdict, category=j.category, confidence=j.confidence,  # type: ignore[arg-type]
                        reason="(replayed verdict)")


def replay(pipeline: ScanPipeline, req: ReplayRequest) -> ReplayResult:
    rec = req.recorded.explanation
    if content_hmac(content_key(), req.text) != rec.content_hmac:
        return ReplayResult(content_matches=False, identical=False, recorded_decision=req.recorded.decision,
                            replayed_decision=None, recorded_decided_by=rec.decided_by, replayed_decided_by=None,
                            differences=["the text does not match the recorded content hash; nothing was replayed"],
                            versions=[], versions_identical=False, judge_source="not_needed", explanation=None)
    judge_was_usable = rec.classifier is not None and rec.classifier.band_low is not None
    override = None
    if not req.live_judge and pipeline.cascade is not None:
        model = (rec.judge.model if rec.judge and rec.judge.model else rec.versions.get("judge_model")) or "unknown"
        prompt = (rec.judge.prompt_version if rec.judge and rec.judge.prompt_version
                  else rec.versions.get("judge_prompt")) or "unknown"
        override = RecordedJudge(_recorded_verdict(rec), model, prompt)
    result = pipeline.scan(
        ScanRequest(text=req.text, direction=req.direction, organization_id=req.organization_id, context=req.context,
                    policy=req.policy),
        vault=InMemoryTokenVault(), judge_override=override, force_no_judge=not judge_was_usable)
    new = result.explanation
    assert new is not None  # every scan result carries an explanation
    diffs: list[str] = []
    if result.decision is not req.recorded.decision:
        diffs.append(f"decision: recorded {req.recorded.decision.value}, replayed {result.decision.value}")
    if new.decided_by != rec.decided_by or new.tier != rec.tier:
        diffs.append(f"decided by: recorded {rec.decided_by} (tier {rec.tier}), replayed {new.decided_by} (tier {new.tier})")
    rec_entities = {f.entity.value for f in rec.detectors_fired}
    new_entities = {f.entity.value for f in new.detectors_fired}
    if rec_entities != new_entities:
        diffs.append(f"entities: recorded {sorted(rec_entities)}, replayed {sorted(new_entities)}")
    if result.failed_closed and result.fail_closed_reason == "judge_verdict_not_recorded":
        diffs.append("the replay needed a judge verdict the event did not record (re-run with live_judge to ask again)")
    if rec.classifier and new.classifier and abs(rec.classifier.score - new.classifier.score) > 1e-4:
        diffs.append(f"classifier score: recorded {rec.classifier.score}, replayed {new.classifier.score} (information)")
    names = sorted(set(rec.versions) | set(new.versions))
    versions = [VersionDiff(name=n, recorded=rec.versions.get(n), current=new.versions.get(n),
                            same=rec.versions.get(n) == new.versions.get(n)) for n in names]
    judge_source = ("not_needed" if new.judge is None or new.judge.verdict is None
                    else "recorded" if new.judge.skipped_reason == "replayed" else "live")
    identical = (result.decision is req.recorded.decision and new.decided_by == rec.decided_by
                 and rec_entities == new_entities)
    return ReplayResult(content_matches=True, identical=identical, recorded_decision=req.recorded.decision,
                        replayed_decision=result.decision, recorded_decided_by=rec.decided_by,
                        replayed_decided_by=new.decided_by, differences=diffs, versions=versions,
                        versions_identical=all(v.same for v in versions), judge_source=judge_source,
                        explanation=new.storable())
