from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from app.models import Action, Detection, Direction, EntityType, Location, RequestContext, Severity
from app.policies import Policy, PolicyRule, RuleScope, TimeWindow, baseline_action, evaluate


def det(entity=EntityType.EMAIL, severity=Severity.MEDIUM, conf=0.95) -> Detection:
    return Detection(entity=entity, confidence=conf, severity=severity, location=Location(start=0, end=5),
                     detector="t", detector_version="1")


CTX = RequestContext(user_id="u1", team="eng", application="chat", provider="gemini", model="m1",
                     environment="production", ip="10.1.2.3")
NOW = datetime(2026, 9, 19, 12, 30, tzinfo=timezone.utc)


def resolve(policy, d=None, ctx=CTX, direction=Direction.INPUT):
    return evaluate([d or det()], policy, ctx, direction, NOW)[0]


def test_baseline_by_severity_and_threats():
    assert baseline_action(det(severity=Severity.CRITICAL)) is Action.BLOCK
    assert baseline_action(det(severity=Severity.HIGH)) is Action.REDACT
    assert baseline_action(det(severity=Severity.MEDIUM)) is Action.MASK
    assert baseline_action(det(severity=Severity.LOW)) is Action.ALLOW
    assert baseline_action(det(EntityType.JAILBREAK, Severity.LOW)) is Action.BLOCK


def test_rule_overrides_baseline():
    p = Policy(policy_id="p", rules=[PolicyRule(entity=EntityType.EMAIL, action=Action.TOKENIZE)])
    r = resolve(p)
    assert r.action is Action.TOKENIZE and r.matched_rule


def test_deny_overrides_when_multiple_rules_match():
    p = Policy(policy_id="p", rules=[PolicyRule(entity=EntityType.EMAIL, action=Action.ALLOW),
                                     PolicyRule(entity=EntityType.EMAIL, action=Action.REDACT)])
    assert resolve(p).action is Action.REDACT


def test_min_confidence_unmet_falls_back_to_baseline_not_allow():
    p = Policy(policy_id="p", rules=[PolicyRule(entity=EntityType.EMAIL, action=Action.ALLOW, min_confidence=0.99)])
    r = resolve(p)
    assert r.action is Action.MASK and not r.matched_rule


@pytest.mark.parametrize("entity", [EntityType.API_KEY, EntityType.PRIVATE_KEY, EntityType.CREDIT_CARD,
                                    EntityType.PASSWORD, EntityType.PROMPT_INJECTION])
def test_allow_rejected_at_load_time_for_critical_entities(entity):
    with pytest.raises(ValidationError):
        PolicyRule(entity=entity, action=Action.ALLOW)


def test_allow_rejected_when_rule_severity_is_critical():
    with pytest.raises(ValidationError):
        PolicyRule(entity=EntityType.EMAIL, action=Action.ALLOW, severity=Severity.CRITICAL)


def test_evaluation_time_floor_even_if_validation_is_bypassed():
    rule = PolicyRule.model_construct(entity=EntityType.API_KEY, action=Action.ALLOW, severity=None,
                                      min_confidence=0.0, scope=None)  # bypasses validators
    p = Policy.model_construct(policy_id="p", organization_id=None, version=1, rules=[rule])
    assert resolve(p, det(EntityType.API_KEY, Severity.CRITICAL)).action is Action.BLOCK


def test_rule_severity_is_a_floor():
    p = Policy(policy_id="p", rules=[PolicyRule(entity=EntityType.EMAIL, action=Action.MASK, severity=Severity.HIGH)])
    assert resolve(p).severity is Severity.HIGH


@pytest.mark.parametrize("scope,matches", [
    (RuleScope(users=["u1"]), True), (RuleScope(users=["u2"]), False),
    (RuleScope(teams=["eng"]), True), (RuleScope(applications=["other"]), False),
    (RuleScope(providers=["gemini"]), True), (RuleScope(providers=["openai"]), False),
    (RuleScope(models=["m1"]), True), (RuleScope(environments=["production"]), True),
    (RuleScope(environments=["dev"]), False),
    (RuleScope(ip_cidrs=["10.0.0.0/8"]), True), (RuleScope(ip_cidrs=["192.168.0.0/16"]), False),
    (RuleScope(time_window_utc=TimeWindow(start="09:00", end="18:00")), True),
    (RuleScope(time_window_utc=TimeWindow(start="18:00", end="09:00")), False),
    (RuleScope(time_window_utc=TimeWindow(start="22:00", end="13:00")), True),  # wraps midnight
    (RuleScope(directions=[Direction.OUTPUT]), False),
])
def test_scope_matching(scope, matches):
    p = Policy(policy_id="p", rules=[PolicyRule(entity=EntityType.EMAIL, action=Action.REDACT, scope=scope)])
    assert resolve(p).matched_rule is matches


def test_missing_context_never_matches_a_scoped_rule():
    p = Policy(policy_id="p", rules=[PolicyRule(entity=EntityType.EMAIL, action=Action.ALLOW,
                                                scope=RuleScope(teams=["eng"]))])
    r = resolve(p, ctx=RequestContext())
    assert r.action is Action.MASK and not r.matched_rule  # falls to baseline, never to ALLOW


def test_invalid_policy_inputs_rejected():
    with pytest.raises(ValidationError):
        RuleScope(ip_cidrs=["not-a-cidr"])
    with pytest.raises(ValidationError):
        TimeWindow(start="25:00", end="10:00")
    with pytest.raises(ValidationError):
        Policy.model_validate({"policy_id": "p", "unknown_field": 1})   # untyped input, as it arrives over the API
