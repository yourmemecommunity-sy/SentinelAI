"""Explainable risk scoring.

risk = max(data sensitivity, threat) + volume + context, capped at 100.
Sanitized detections count at half weight (the sensitive value never reaches the model); withheld
(BLOCK/QUARANTINE) and allowed detections count in full. A CRITICAL risk level escalates the
decision to BLOCK regardless of policy - the risk engine can only make a decision stricter.
"""
from __future__ import annotations

from app.models.types import THREAT_ENTITIES, Action, Direction, RequestContext, Risk, RiskFactor, RiskLevel, Severity
from app.policies.evaluator import ResolvedDetection

_SEVERITY_WEIGHT = {Severity.LOW: 10, Severity.MEDIUM: 30, Severity.HIGH: 60, Severity.CRITICAL: 85}
_MITIGATION = 0.5
_LOCAL_PROVIDERS = {"ollama"}


def _level(score: int) -> RiskLevel:
    if score >= 80:
        return RiskLevel.CRITICAL
    if score >= 60:
        return RiskLevel.HIGH
    if score >= 30:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


def _weight(r: ResolvedDetection) -> float:
    w = _SEVERITY_WEIGHT[r.severity] * r.detection.confidence
    return w * _MITIGATION if r.action.sanitizes else w


def assess(resolved: list[ResolvedDetection], policy_decision: Action, ctx: RequestContext,
           direction: Direction) -> Risk:
    if not resolved:
        return Risk(risk_score=0, risk_level=RiskLevel.LOW, decision=policy_decision, factors=[])

    factors: list[RiskFactor] = []
    data = [r for r in resolved if r.detection.entity not in THREAT_ENTITIES]
    threats = [r for r in resolved if r.detection.entity in THREAT_ENTITIES]

    sensitivity = max((_weight(r) for r in data), default=0.0)
    threat = max((_weight(r) for r in threats), default=0.0)
    if data:
        top = max(data, key=_weight)
        factors.append(RiskFactor(name="data_sensitivity", contribution=round(sensitivity, 1),
                                  detail=f"highest: {top.detection.entity.value} ({top.severity.value}), "
                                         f"action {top.action.value}"))
    if threats:
        top = max(threats, key=_weight)
        factors.append(RiskFactor(name="threat_probability", contribution=round(threat, 1),
                                  detail=f"highest: {top.detection.entity.value} "
                                         f"(confidence {top.detection.confidence:.2f})"))
    base = max(sensitivity, threat)

    volume = float(min(10, 2 * (len(resolved) - 1)))
    if volume:
        factors.append(RiskFactor(name="detection_volume", contribution=volume,
                                  detail=f"{len(resolved)} detections in one request"))

    context = 0.0
    if ctx.provider and ctx.provider.lower() not in _LOCAL_PROVIDERS:
        context += 5
        factors.append(RiskFactor(name="model_context", contribution=5.0,
                                  detail="content would leave the organization boundary to an external provider"))
    if (ctx.environment or "").lower() in ("prod", "production"):
        context += 3
        factors.append(RiskFactor(name="user_context", contribution=3.0, detail="production environment"))
    if not ctx.user_id:
        context += 2
        factors.append(RiskFactor(name="user_context", contribution=2.0, detail="request not attributed to a user"))
    if direction is Direction.OUTPUT and any(r.detection.entity not in THREAT_ENTITIES
                                             and r.severity is Severity.CRITICAL for r in resolved):
        context += 3
        factors.append(RiskFactor(name="output_leakage", contribution=3.0,
                                  detail="critical data present in model output"))

    score = min(100, round(base + volume + context))
    level = _level(score)
    decision = policy_decision
    if level is RiskLevel.CRITICAL and not policy_decision.withholds_content:
        decision = Action.BLOCK
        factors.append(RiskFactor(name="risk_escalation", contribution=0.0,
                                  detail=f"CRITICAL risk escalated {policy_decision.value} to BLOCK"))
    return Risk(risk_score=score, risk_level=level, decision=decision, factors=factors)
