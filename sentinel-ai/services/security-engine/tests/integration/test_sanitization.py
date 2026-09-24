import pytest

from app.models import Action, EntityType, ScanRequest
from app.policies import Policy, PolicyRule
from app.sanitization import InMemoryTokenVault
from conftest import fake_aws_key, valid_card


def scan(pipeline, text, rules=None, vault=None):
    policy = Policy(policy_id="t", rules=rules) if rules is not None else None
    return pipeline.scan(ScanRequest(text=text, organization_id="org", policy=policy), vault)


def test_mask_email_matches_spec_example(pipeline):
    r = scan(pipeline, "My email is user@example.com")
    assert r.decision is Action.MASK and r.sanitized_text == "My email is u***@example.com"


def test_redact_and_tokenize_and_hash(pipeline):
    red = scan(pipeline, "My email is user@example.com", [PolicyRule(entity=EntityType.EMAIL, action=Action.REDACT)])
    assert red.sanitized_text == "My email is [EMAIL_REDACTED]"

    vault = InMemoryTokenVault()
    tok = scan(pipeline, "a user@example.com b user@example.com c other@example.com",
               [PolicyRule(entity=EntityType.EMAIL, action=Action.TOKENIZE)], vault)
    assert tok.sanitized_text == "a <EMAIL_TOKEN_001> b <EMAIL_TOKEN_001> c <EMAIL_TOKEN_002>"
    assert vault.restore(tok.sanitized_text) == "a user@example.com b user@example.com c other@example.com"

    h = scan(pipeline, "My email is user@example.com", [PolicyRule(entity=EntityType.EMAIL, action=Action.HASH)])
    assert h.sanitized_text.startswith("My email is <EMAIL_HASH:") and "user@example.com" not in h.sanitized_text


def test_credit_card_blocked_by_default_but_tokenizable_by_policy(pipeline):
    card = valid_card()
    assert scan(pipeline, f"card {card}").decision is Action.BLOCK
    r = scan(pipeline, f"card {card}", [PolicyRule(entity=EntityType.CREDIT_CARD, action=Action.TOKENIZE)])
    assert r.decision is Action.TOKENIZE and card not in r.sanitized_text


def test_secret_masking_is_escalated_to_full_redaction(pipeline):
    r = scan(pipeline, f"key {fake_aws_key()} end", [PolicyRule(entity=EntityType.AWS_CREDENTIAL, action=Action.MASK)])
    assert fake_aws_key() not in (r.sanitized_text or "")
    assert not r.sanitized_text or "AKIA" not in r.sanitized_text


def test_overlapping_detections_leave_no_fragment(pipeline):
    text = "connect postgresql://app:hunter2pw@db.example.com:5432/x now"
    r = scan(pipeline, text, [PolicyRule(entity=EntityType.CONNECTION_STRING, action=Action.REDACT),
                              PolicyRule(entity=EntityType.PASSWORD, action=Action.REDACT)])
    assert r.decision is not Action.BLOCK
    assert "hunter2pw" not in r.sanitized_text and "db.example.com" not in r.sanitized_text


def test_last4_mask_keeps_only_last_four(pipeline):
    r = scan(pipeline, "reach me on +1 415 555 0132")
    assert r.sanitized_text.endswith("0132") and "415" not in r.sanitized_text


def test_sanitized_output_is_rescanned_clean(pipeline):
    r = scan(pipeline, "email a@example.com and phone 9876543210 and dob: 14/03/1990")
    again = scan(pipeline, r.sanitized_text)
    assert not any(d.entity in {EntityType.EMAIL, EntityType.PHONE, EntityType.DATE_OF_BIRTH} for d in again.detections)


@pytest.mark.parametrize("text", ["", "   ", "plain text with nothing sensitive"])
def test_clean_text_passes_unchanged(pipeline, text):
    r = scan(pipeline, text)
    assert r.decision is Action.ALLOW and r.sanitized_text == text and not r.detections
