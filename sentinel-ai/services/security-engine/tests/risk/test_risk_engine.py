from app.models import Action, Detection, Direction, EntityType, Location, RequestContext, RiskLevel, Severity
from app.policies import ResolvedDetection
from app.risk import assess


def rd(entity, severity, action, conf=0.98):
    d = Detection(entity=entity, confidence=conf, severity=severity, location=Location(start=0, end=4),
                  detector="t", detector_version="1")
    return ResolvedDetection(d, action, severity, False)


CTX = RequestContext(user_id="u1", provider="gemini")


def test_no_detections_is_low_and_keeps_decision():
    r = assess([], Action.ALLOW, CTX, Direction.INPUT)
    assert (r.risk_score, r.risk_level, r.decision) == (0, RiskLevel.LOW, Action.ALLOW)


def test_critical_secret_blocked_is_critical():
    r = assess([rd(EntityType.PRIVATE_KEY, Severity.CRITICAL, Action.BLOCK)], Action.BLOCK, CTX, Direction.INPUT)
    assert r.risk_level is RiskLevel.CRITICAL and r.decision is Action.BLOCK and r.risk_score >= 80


def test_sanitized_detection_counts_at_half_weight():
    blocked = assess([rd(EntityType.CREDIT_CARD, Severity.CRITICAL, Action.BLOCK)], Action.BLOCK, CTX, Direction.INPUT)
    tokenized = assess([rd(EntityType.CREDIT_CARD, Severity.CRITICAL, Action.TOKENIZE)], Action.TOKENIZE, CTX, Direction.INPUT)
    assert tokenized.risk_score < blocked.risk_score
    assert tokenized.decision is Action.TOKENIZE  # mitigated, so risk does not escalate


def test_critical_risk_escalates_a_non_withholding_decision():
    r = assess([rd(EntityType.PRIVATE_KEY, Severity.CRITICAL, Action.ALLOW)], Action.ALLOW, CTX, Direction.INPUT)
    assert r.decision is Action.BLOCK
    assert any(f.name == "risk_escalation" for f in r.factors)


def test_risk_never_relaxes_a_decision():
    r = assess([rd(EntityType.EMAIL, Severity.MEDIUM, Action.BLOCK)], Action.BLOCK, CTX, Direction.INPUT)
    assert r.decision is Action.BLOCK


def test_factors_are_explainable_and_contain_no_values():
    r = assess([rd(EntityType.EMAIL, Severity.MEDIUM, Action.MASK), rd(EntityType.PHONE, Severity.MEDIUM, Action.MASK)],
               Action.MASK, RequestContext(provider="openai", environment="production"), Direction.INPUT)
    names = {f.name for f in r.factors}
    assert {"data_sensitivity", "detection_volume", "model_context", "user_context"} <= names


def test_local_provider_gets_no_external_penalty():
    ext = assess([rd(EntityType.EMAIL, Severity.MEDIUM, Action.MASK)], Action.MASK, RequestContext(user_id="u", provider="openai"), Direction.INPUT)
    loc = assess([rd(EntityType.EMAIL, Severity.MEDIUM, Action.MASK)], Action.MASK, RequestContext(user_id="u", provider="ollama"), Direction.INPUT)
    assert loc.risk_score < ext.risk_score


def test_score_is_capped_at_100():
    many = [rd(EntityType.AWS_CREDENTIAL, Severity.CRITICAL, Action.BLOCK, 1.0) for _ in range(30)]
    assert assess(many, Action.BLOCK, RequestContext(provider="openai", environment="prod"), Direction.OUTPUT).risk_score == 100
