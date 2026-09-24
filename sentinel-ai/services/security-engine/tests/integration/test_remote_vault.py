"""TOKENIZE against a session-scoped token vault (a stub HTTP server speaking the vault's wire protocol)."""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from app.config.settings import Settings
from app.models import Action, EntityType, ScanRequest
from app.pipelines import ScanPipeline
from app.detectors.registry import default_registry
from app.policies import Policy, PolicyRule
from app.sanitization import RemoteTokenVault, VaultUnavailableError
from conftest import fake_aws_key

TOKENIZABLE = {"EMAIL", "NAME"}   # the stub refuses everything else (e.g. PHONE), like the real vault refuses credentials
TOKEN = "engine-to-vault-token-1234"


class StubVault:
    """Speaks POST /v1/vault/tokenize like the real service (deterministic per session, refuses non-tokenizable types)."""

    def __init__(self, mode="ok"):
        self.mode = mode
        self.requests: list[dict] = []
        self.headers: list[dict] = []
        self.maps: dict[tuple, dict] = {}
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                raw = self.rfile.read(int(self.headers.get("content-length", 0)))
                body = json.loads(raw)
                outer.requests.append(body)
                outer.headers.append({k.lower(): v for k, v in self.headers.items()})
                if outer.mode == "redirect":
                    self.send_response(307)
                    self.send_header("location", "http://127.0.0.1:9/steal")
                    self.end_headers()
                    return
                if outer.mode.startswith("http_"):
                    self.send_response(int(outer.mode[5:]))
                    self.end_headers()
                    return
                if outer.mode == "garbage":
                    out = b"not json"
                elif outer.mode in ("wronglen", "badtoken"):
                    out = json.dumps({"tokens": ["[TOK_EMAIL_1]"] * (len(body["items"]) + 1) if outer.mode == "wronglen" else ["EMAIL_1"] * len(body["items"])}).encode()
                else:
                    session = outer.maps.setdefault((body["organization_id"], body["session_id"]), {})
                    toks: list[str | None] = []
                    for it in body["items"]:
                        if it["entity"] not in TOKENIZABLE:
                            toks.append(None)
                            continue
                        n = sum(1 for k in session if k[0] == it["entity"])
                        toks.append(session.setdefault((it["entity"], it["value"]), f"[TOK_{it['entity']}_{n + 1}]"))
                    out = json.dumps({"tokens": toks}).encode()
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def stub():
    v = StubVault()
    yield v
    v.close()


def pipe(url, token=TOKEN, timeout=1.0):
    return ScanPipeline(default_registry(), Settings(vault_url=url, vault_token=token, vault_timeout_s=timeout))


def scan(p, text, rules, session="sess-1", org="org-1"):
    return p.scan(ScanRequest(text=text, organization_id=org, vault_session=session, policy=Policy(policy_id="t", rules=rules)))


EMAIL_TOK = [PolicyRule(entity=EntityType.EMAIL, action=Action.TOKENIZE)]


def test_tokenize_uses_the_vault_and_the_same_value_gets_the_same_token(stub):
    p = pipe(stub.url)
    r = scan(p, "a user@example.com b user@example.com c other@example.com", EMAIL_TOK)
    assert r.sanitized_text == "a [TOK_EMAIL_1] b [TOK_EMAIL_1] c [TOK_EMAIL_2]"
    assert r.decision is Action.TOKENIZE and not r.failed_closed
    again = scan(p, "later: other@example.com", EMAIL_TOK)                       # same session, next request
    assert again.sanitized_text == "later: [TOK_EMAIL_2]"


def test_one_round_trip_per_scan_and_the_request_names_org_session_and_partial_refusal(stub):
    p = pipe(stub.url)
    scan(p, "x@example.com y@example.com z@example.com", EMAIL_TOK)
    assert len(stub.requests) == 1
    req = stub.requests[0]
    assert req["organization_id"] == "org-1" and req["session_id"] == "sess-1" and req["refuse"] == "null"
    assert [i["value"] for i in req["items"]] == ["x@example.com", "y@example.com", "z@example.com"]
    assert stub.headers[0]["x-internal-token"] == TOKEN


def test_sessions_are_passed_through_untouched_so_isolation_is_the_vaults_job(stub):
    p = pipe(stub.url)
    a = scan(p, "same@example.com", EMAIL_TOK, session="s-a", org="org-1")
    b = scan(p, "same@example.com", EMAIL_TOK, session="s-b", org="org-2")
    assert a.sanitized_text == b.sanitized_text == "[TOK_EMAIL_1]"
    assert {(r["organization_id"], r["session_id"]) for r in stub.requests} == {("org-1", "s-a"), ("org-2", "s-b")}


def test_a_type_the_vault_refuses_is_redacted_while_others_are_tokenized(stub):
    rules = [PolicyRule(entity=EntityType.PHONE, action=Action.TOKENIZE), *EMAIL_TOK]
    r = scan(pipe(stub.url), "call +1 415 555 0132 or mail a@example.com", rules)
    assert r.sanitized_text == "call [PHONE_REDACTED] or mail [TOK_EMAIL_1]"
    assert "415" not in r.sanitized_text and not r.failed_closed


def test_a_credential_with_a_tokenize_policy_is_never_tokenized_and_never_leaked(stub):
    key = fake_aws_key()
    r = scan(pipe(stub.url), f"key {key}", [PolicyRule(entity=EntityType.AWS_CREDENTIAL, action=Action.TOKENIZE)])
    assert r.sanitized_text is None or (key not in r.sanitized_text and "[TOK_" not in r.sanitized_text)


def test_no_tokenize_action_means_no_vault_traffic(stub):
    r = scan(pipe(stub.url), "mail a@example.com", [PolicyRule(entity=EntityType.EMAIL, action=Action.MASK)])
    assert r.sanitized_text == "mail a***@example.com"
    assert stub.requests == []


def test_a_request_without_a_session_never_touches_the_vault(stub):
    p = pipe(stub.url)
    r = p.scan(ScanRequest(text="a user@example.com", organization_id="o", policy=Policy(policy_id="t", rules=EMAIL_TOK)))
    assert r.sanitized_text == "a <EMAIL_TOKEN_001>" and stub.requests == []     # one-way, in-process, never exposed


def test_session_without_a_configured_vault_degrades_to_redaction():
    p = ScanPipeline(default_registry(), Settings())
    r = scan(p, "mail a@example.com", EMAIL_TOK)
    assert r.sanitized_text == "mail [EMAIL_REDACTED]" and not r.failed_closed


@pytest.mark.parametrize("mode", ["http_500", "http_503", "http_401", "http_413", "garbage", "wronglen", "badtoken", "redirect"])
def test_every_vault_failure_fails_closed_with_no_text(mode):
    v = StubVault(mode)
    try:
        r = scan(pipe(v.url), "mail a@example.com", EMAIL_TOK)
    finally:
        v.close()
    assert r.decision is Action.BLOCK and r.failed_closed and r.fail_closed_reason == "vault_unavailable"
    assert r.sanitized_text is None


def test_unreachable_vault_fails_closed():
    r = scan(pipe("http://127.0.0.1:9", timeout=0.3), "mail a@example.com", EMAIL_TOK)
    assert r.failed_closed and r.fail_closed_reason == "vault_unavailable" and r.sanitized_text is None


def test_redirects_are_never_followed_so_the_token_is_not_forwarded():
    v = StubVault("redirect")
    try:
        with pytest.raises(VaultUnavailableError):
            RemoteTokenVault(v.url, TOKEN, "o", "s").token_for("EMAIL", "a@example.com")
        assert len(v.requests) == 1
    finally:
        v.close()


def test_timeout_is_enforced():
    hang = threading.Event()

    class Slow(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            hang.wait(3)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Slow)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        import time

        t0 = time.perf_counter()
        r = scan(pipe(f"http://127.0.0.1:{srv.server_address[1]}", timeout=0.2), "mail a@example.com", EMAIL_TOK)
        assert r.failed_closed and time.perf_counter() - t0 < 2.0
    finally:
        hang.set()
        srv.shutdown()
        srv.server_close()


def test_the_response_and_errors_never_contain_the_raw_value(stub):
    r = scan(pipe(stub.url), "mail secret.person@example.com", EMAIL_TOK)
    assert "secret.person" not in r.model_dump_json()
    v = StubVault("http_500")
    try:
        r = scan(pipe(v.url), "mail secret.person@example.com", EMAIL_TOK)
        assert "secret.person" not in r.model_dump_json()
    finally:
        v.close()


def test_vault_session_is_validated_on_the_wire_model():
    for bad in ["", "a b", "s\n", "x" * 129, "../etc"]:
        with pytest.raises(Exception):
            ScanRequest(text="x", organization_id="o", vault_session=bad)
    ScanRequest(text="x", organization_id="o", vault_session="ok:session_1.2-3")


def test_production_settings_require_a_vault_token_when_a_vault_is_configured(monkeypatch):
    for k in ["SENTINEL_ENV", "SECURITY_ENGINE_TOKEN", "VAULT_URL", "VAULT_TOKEN"]:
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("SENTINEL_ENV", "production")
    monkeypatch.setenv("SECURITY_ENGINE_TOKEN", "e" * 20)
    monkeypatch.setenv("VAULT_URL", "http://vault:8004")
    with pytest.raises(RuntimeError):
        Settings.from_env()
    monkeypatch.setenv("VAULT_TOKEN", "v" * 20)
    assert Settings.from_env().vault_url == "http://vault:8004"
