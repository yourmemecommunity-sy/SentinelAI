"""Policy evaluation: detections + policy + request context -> resolved action per detection."""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime, timezone

from app.models.types import (
    NEVER_ALLOW_ENTITIES, THREAT_ENTITIES, Action, Detection, Direction, RequestContext, Severity,
)
from app.policies.policy import Policy, PolicyRule, RuleScope

BASELINE_POLICY_ID = "sentinelai-baseline"


@dataclass(frozen=True)
class ResolvedDetection:
    detection: Detection
    action: Action
    severity: Severity  # max(detection severity, rule severity floor)
    matched_rule: bool


def baseline_action(detection: Detection, severity: Severity | None = None) -> Action:
    """Severity-based default used when no rule matches. Threat signals are always blocked."""
    if detection.entity in THREAT_ENTITIES:
        return Action.BLOCK
    sev = severity or detection.severity
    return {
        Severity.CRITICAL: Action.BLOCK,
        Severity.HIGH: Action.REDACT,
        Severity.MEDIUM: Action.MASK,
        Severity.LOW: Action.ALLOW,
    }[sev]


def _in_time_window(now: datetime, start: str, end: str) -> bool:
    cur = now.hour * 60 + now.minute
    s = int(start[:2]) * 60 + int(start[3:])
    e = int(end[:2]) * 60 + int(end[3:])
    return s <= cur < e if s <= e else (cur >= s or cur < e)


def _scope_matches(scope: RuleScope | None, ctx: RequestContext, direction: Direction, now: datetime) -> bool:
    """A scoped dimension with no corresponding context value does NOT match (rule simply does not apply)."""
    if scope is None:
        return True
    pairs = [
        (scope.users, ctx.user_id), (scope.teams, ctx.team), (scope.applications, ctx.application),
        (scope.providers, ctx.provider), (scope.models, ctx.model), (scope.environments, ctx.environment),
    ]
    for allowed, value in pairs:
        if allowed is not None and (value is None or value not in allowed):
            return False
    if scope.directions is not None and direction not in scope.directions:
        return False
    if scope.ip_cidrs is not None:
        if ctx.ip is None:
            return False
        try:
            addr = ipaddress.ip_address(ctx.ip)
        except ValueError:
            return False
        if not any(addr in ipaddress.ip_network(c, strict=False) for c in scope.ip_cidrs):
            return False
    if scope.time_window_utc is not None and not _in_time_window(now, scope.time_window_utc.start,
                                                                 scope.time_window_utc.end):
        return False
    return True


def _rule_applies(rule: PolicyRule, det: Detection, ctx: RequestContext, direction: Direction,
                  now: datetime) -> bool:
    return (rule.entity is det.entity and det.confidence >= rule.min_confidence
            and _scope_matches(rule.scope, ctx, direction, now))


def evaluate(detections: list[Detection], policy: Policy, ctx: RequestContext, direction: Direction,
             now: datetime | None = None) -> list[ResolvedDetection]:
    now = now or datetime.now(timezone.utc)
    resolved: list[ResolvedDetection] = []
    for det in detections:
        matches = [r for r in policy.rules if _rule_applies(r, det, ctx, direction, now)]
        if not matches:
            resolved.append(ResolvedDetection(det, baseline_action(det), det.severity, False))
            continue
        action = max((r.action for r in matches), key=lambda a: a.rank)  # deny-overrides
        severity = max([det.severity, *(r.severity for r in matches if r.severity)], key=lambda s: s.rank)
        if action is Action.ALLOW and (det.severity is Severity.CRITICAL or det.entity in NEVER_ALLOW_ENTITIES
                                       or det.entity in THREAT_ENTITIES):
            action = baseline_action(det, severity)  # evaluation-time floor
        resolved.append(ResolvedDetection(det, action, severity, True))
    return resolved
