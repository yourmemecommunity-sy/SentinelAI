from fastapi.testclient import TestClient

from app.config.settings import Settings
from app.main import create_app
from conftest import fake_aws_key


def client(**settings) -> TestClient:
    return TestClient(create_app(Settings(**settings)))


def test_health_and_ready():
    c = client()
    assert c.get("/health").json()["status"] == "alive"
    r = c.get("/ready")
    assert r.status_code == 200 and r.json()["status"] == "ready"


def test_scan_blocks_secret_and_returns_structured_evidence():
    body = {"text": f"deploy with {fake_aws_key()}", "organization_id": "org-1", "direction": "INPUT"}
    r = client().post("/v1/scan", json=body)
    assert r.status_code == 200
    data = r.json()
    assert data["decision"] == "BLOCK" and data["sanitized_text"] is None and not data["failed_closed"]
    d = data["detections"][0]
    assert d["entity"] == "AWS_CREDENTIAL" and d["severity"] == "CRITICAL" and {"start", "end"} <= set(d["location"])
    assert fake_aws_key() not in r.text
    assert data["risk"]["risk_level"] == "CRITICAL" and data["risk"]["factors"]


def test_scan_with_inline_policy():
    body = {"text": "mail a@example.com", "organization_id": "o", "policy": {
        "policy_id": "eng", "rules": [{"entity": "EMAIL", "action": "REDACT", "severity": "MEDIUM"}]}}
    data = client().post("/v1/scan", json=body).json()
    assert data["decision"] == "REDACT" and data["policy_id"] == "eng" and data["sanitized_text"] == "mail [EMAIL_REDACTED]"


def test_invalid_input_is_rejected_not_scanned():
    c = client()
    assert c.post("/v1/scan", json={"text": "x"}).status_code == 422                       # no org
    assert c.post("/v1/scan", json={"text": "x", "organization_id": "o", "extra": 1}).status_code == 422
    bad_policy = {"text": "x", "organization_id": "o", "policy": {
        "policy_id": "p", "rules": [{"entity": "API_KEY", "action": "ALLOW"}]}}
    assert c.post("/v1/scan", json=bad_policy).status_code == 422  # unsafe ALLOW rejected


def test_internal_token_enforced_when_configured():
    c = client(internal_token="s3cr3t-internal")
    body = {"text": "hi", "organization_id": "o"}
    assert c.post("/v1/scan", json=body).status_code == 401
    assert c.post("/v1/scan", json=body, headers={"X-Internal-Token": "wrong"}).status_code == 401
    assert c.post("/v1/scan", json=body, headers={"X-Internal-Token": "s3cr3t-internal"}).status_code == 200


def test_production_without_token_refuses_to_start(monkeypatch):
    import pytest
    monkeypatch.setenv("SENTINEL_ENV", "production")
    monkeypatch.delenv("SECURITY_ENGINE_TOKEN", raising=False)
    with pytest.raises(RuntimeError):
        Settings.from_env()
