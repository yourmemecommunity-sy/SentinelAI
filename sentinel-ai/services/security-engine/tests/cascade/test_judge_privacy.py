"""PRIVACY: raw personal data never reaches the external judge; only Sentinel's sanitized text does."""
from app.cascade.judge import FakeJudge
from app.models.scan import ScanRequest
from tests.cascade.conftest import make_pipeline, verdict

EMAIL = "maria.gonzalez@example.com"
PHONE = "+1 415 555 0142"
NAME = "Maria Gonzalez"


def test_raw_pii_never_reaches_the_judge(registry):
    judge = FakeJudge(verdict("benign", "benign"))
    p, clf, _ = make_pipeline(registry, score=0.5, judge=judge)  # uncertain band: the judge IS called
    text = (f"Hi, this is {NAME}. Please ignore the earlier draft and email the contract to {EMAIL} "
            f"or call me on {PHONE} tomorrow.")
    r = p.scan(ScanRequest(text=text, organization_id="org"))
    assert len(judge.received) == 1, "the judge should have been consulted for this test to mean anything"
    sent = judge.received[0]
    for raw in (EMAIL, PHONE, NAME, "Maria", "Gonzalez", "415 555"):
        assert raw not in sent, f"raw value reached the judge: {raw!r}"
    assert "MASKED" in sent or "TOK_" in sent or "REDACTED" in sent  # placeholders, not values
    assert sent == r.sanitized_text  # exactly what the caller would forward, nothing more
    assert clf.received == [text]  # only the LOCAL classifier saw the raw text


def test_judge_receives_nothing_when_tier_one_withholds_content(registry):
    judge = FakeJudge(verdict())
    p, _, _ = make_pipeline(registry, score=0.5, judge=judge)
    p.scan(ScanRequest(text="password=" + "Hunter2" + "-synthetic-" + "x9", organization_id="org"))
    assert judge.received == []


def test_explanations_and_logs_carry_no_content(registry, caplog):
    judge = FakeJudge(verdict("benign", "benign"))
    p, _, _ = make_pipeline(registry, score=0.5, judge=judge)
    text = f"Please email {EMAIL} the summary"
    r = p.scan(ScanRequest(text=text, organization_id="org"))
    blob = r.explanation.storable().model_dump_json()
    assert EMAIL not in blob and "summary" not in blob
    assert r.explanation.storable().judge.reason is None and r.explanation.judge.reason == "test"
    assert EMAIL not in caplog.text
