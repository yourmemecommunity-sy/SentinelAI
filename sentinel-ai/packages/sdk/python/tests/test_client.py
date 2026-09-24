import json
import pickle
import threading
import time
from typing import Any
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from urllib.parse import unquote

from sentinelai import (
    Sentinel, SentinelAuthenticationError, SentinelBlockedError, SentinelConfigError, SentinelError, SentinelPermissionError,
    SentinelProviderError, SentinelRateLimitError, SentinelUnavailableError, SentinelValidationError,
)

# Assembled at runtime: a correctly *shaped* key, not a real credential.
KEY = "snl_" + "abcd1234" + "_" + "A" * 43

CHAT_OK = {"provider": "gemini", "model": "m1", "content": "hello back", "security": {
    "input": {"decision": "MASK", "risk_level": "LOW", "event_id": "e1"},
    "output": {"decision": "ALLOW", "risk_level": "LOW", "event_id": "e2"}}}
SCAN_OK = {"request_id": "r1", "event_id": "e1", "decision": "MASK", "failed_closed": False, "fail_closed_reason": None,
           "sanitized_text": "mail j***@x.co",
           "risk": {"risk_score": 20, "risk_level": "LOW", "decision": "MASK", "factors": [{"name": "data_sensitivity", "contribution": 15, "detail": "EMAIL"}]},
           "detections": [{"entity": "EMAIL", "confidence": 0.95, "severity": "MEDIUM", "location": {"start": 5, "end": 12}, "detector": "pii"}],
           "entity_actions": [], "policy_id": "p"}


class Gateway:
    """A real HTTP server standing in for the gateway. `respond(seen) -> (status, body, headers)`."""

    def __init__(self, respond):
        self.seen: list[dict[str, Any]] = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):  # silence
                pass

            def handle_any(self):
                raw_body = self.rfile.read(int(self.headers.get("content-length", 0)))
                seen = {"method": self.command, "path": self.path, "headers": {k.lower(): v for k, v in self.headers.items()},
                        "body": raw_body.decode("utf-8", "replace"), "raw": raw_body}
                outer.seen.append(seen)
                status, payload, headers = respond(seen)
                raw = payload if isinstance(payload, (bytes, str)) else json.dumps(payload)
                raw = raw.encode() if isinstance(raw, str) else raw
                try:
                    self.send_response(status)
                    for k, v in {"content-type": "application/json", "content-length": str(len(raw)), **headers}.items():
                        self.send_header(k, v)
                    self.end_headers()
                    self.wfile.write(raw)
                except (BrokenPipeError, ConnectionResetError):
                    pass

            # Record EVERY method: a followed redirect is re-issued as GET and must not escape the test double.
            do_POST = do_GET = do_PUT = do_DELETE = do_HEAD = handle_any

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.server.daemon_threads = True
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def gw():
    made = []

    def make(respond):
        g = Gateway(respond)
        made.append(g)
        return g

    yield make
    for g in made:
        g.close()


def ok(payload, status=200, headers=None):
    return lambda seen: (status, payload, headers or {})


def client(url, **kw):
    return Sentinel(api_key=KEY, base_url=url, **kw)


# ---------------------------------------------------------------- secure / chat
def test_secure_sends_bearer_auth_and_maps_response(gw):
    g = gw(ok(CHAT_OK))
    r = client(g.url).secure(provider="gemini", prompt="hi", system="be brief", model="m1", application="app",
                             environment="prod", max_output_tokens=50, temperature=0.2)
    assert (r.content, r.provider, r.model) == ("hello back", "gemini", "m1")
    assert (r.security.input.decision, r.security.input.risk_level, r.security.input.event_id) == ("MASK", "LOW", "e1")
    assert r.security.output.event_id == "e2"
    s = g.seen[0]
    assert s["path"] == "/v1/ai/chat"
    assert s["headers"]["authorization"] == f"Bearer {KEY}"
    assert s["headers"]["user-agent"].startswith("sentinelai-python/")
    assert json.loads(s["body"]) == {
        "provider": "gemini", "model": "m1", "max_output_tokens": 50, "temperature": 0.2, "application": "app", "environment": "prod",
        "messages": [{"role": "system", "content": "be brief"}, {"role": "user", "content": "hi"}]}


def test_blocked_raises_with_metadata_and_no_content(gw):
    g = gw(ok({"error": "blocked", "stage": "output", "decision": "BLOCK", "failed_closed": True, "reason": "engine_timeout", "event_id": "ev9"}, 403))
    with pytest.raises(SentinelBlockedError) as ei:
        client(g.url).secure(provider="openai", prompt="SECRET-PROMPT-TEXT")
    e = ei.value
    assert (e.stage, e.decision, e.failed_closed, e.reason, e.event_id, e.status) == ("output", "BLOCK", True, "engine_timeout", "ev9", 403)
    assert "SECRET-PROMPT-TEXT" not in str(e) + repr(e.__dict__)


@pytest.mark.parametrize("bad", [
    {}, {"content": 5}, {**CHAT_OK, "security": None}, {k: v for k, v in CHAT_OK.items() if k != "content"},
    {**CHAT_OK, "security": {"input": {}, "output": {}}}, "not-an-object", [1],
])
def test_malformed_200_never_returns_content(gw, bad):
    g = gw(ok(bad))
    with pytest.raises(SentinelError):
        client(g.url).secure(provider="gemini", prompt="x")


def test_chat_forwards_full_conversation(gw):
    g = gw(ok(CHAT_OK))
    client(g.url).chat("gemini", [{"role": "user", "content": "a"}, {"role": "assistant", "content": "b"}, {"role": "user", "content": "c"}])
    assert len(json.loads(g.seen[0]["body"])["messages"]) == 3


# ---------------------------------------------------------------- scan / check
def test_scan_returns_evidence_and_sanitized_text(gw):
    g = gw(ok(SCAN_OK))
    r = client(g.url).scan("mail a@b.co", team="eng")
    assert (r.decision, r.blocked, r.sanitized_text, r.risk_level, r.risk_score, r.policy_id, r.event_id) == ("MASK", False, "mail j***@x.co", "LOW", 20, "p", "e1")
    assert (r.detections[0].entity, r.detections[0].start, r.detections[0].end) == ("EMAIL", 5, 12)
    assert r.risk_factors[0].name == "data_sensitivity"
    assert json.loads(g.seen[0]["body"]) == {"text": "mail a@b.co", "direction": "INPUT", "context": {"team": "eng"}}


def test_blocked_scan_is_returned_not_raised(gw):
    r = client(gw(ok({**SCAN_OK, "decision": "BLOCK", "sanitized_text": None})).url).scan("x")
    assert r.blocked and r.sanitized_text is None and r.decision == "BLOCK"


@pytest.mark.parametrize("bad", [{**SCAN_OK, "decision": "BLOCK", "sanitized_text": "leak"}, {**SCAN_OK, "decision": "ALLOW", "sanitized_text": None}])
def test_inconsistent_scan_results_are_rejected(gw, bad):
    with pytest.raises(SentinelError, match="inconsistent decision"):
        client(gw(ok(bad)).url).scan("x")


def test_check_allowed_only_for_unmodified_allow(gw):
    def chk(body):
        return client(gw(ok(body)).url).check("x")
    assert chk({"allowed": True, "decision": "ALLOW", "risk_level": "LOW", "failed_closed": False, "event_id": "e"}).allowed is True
    assert chk({"allowed": True, "decision": "MASK", "risk_level": "LOW", "failed_closed": False, "event_id": "e"}).allowed is False
    assert chk({"allowed": False, "decision": "BLOCK", "risk_level": "CRITICAL", "failed_closed": True, "event_id": None}).allowed is False


# ---------------------------------------------------------------- errors
@pytest.mark.parametrize("status,body,cls", [
    (401, {"error": "unauthorized"}, SentinelAuthenticationError),
    (403, {"error": "forbidden"}, SentinelPermissionError),
    (413, {"error": "payload_too_large"}, SentinelValidationError),
    (422, {"error": "invalid_request", "issues": [{"path": "rules.0", "message": "bad"}]}, SentinelValidationError),
    (502, {"error": "provider_error", "code": "rate_limit", "event_id": "e"}, SentinelProviderError),
    (503, {"error": "audit_unavailable"}, SentinelUnavailableError),
    (500, {"error": "internal_error"}, SentinelUnavailableError),
    (418, {}, SentinelError),
])
def test_http_status_maps_to_typed_error(gw, status, body, cls):
    with pytest.raises(cls) as ei:
        client(gw(ok(body, status)).url).secure(provider="gemini", prompt="x")
    assert ei.value.status == status
    assert KEY not in str(ei.value)


def test_rate_limit_and_validation_details(gw):
    with pytest.raises(SentinelRateLimitError) as ei:
        client(gw(ok({"error": "rate_limited"}, 429, {"retry-after": "7"})).url).scan("x")
    assert ei.value.retry_after_seconds == 7
    with pytest.raises(SentinelValidationError) as vi:
        client(gw(ok({"issues": [{"path": "provider", "message": "bad"}]}, 422)).url).scan("x")
    assert vi.value.issues == [{"path": "provider", "message": "bad"}]


def test_network_failure_timeout_and_non_json_fail_closed(gw):
    dead = gw(ok({}))
    dead.close()
    with pytest.raises(SentinelUnavailableError, match="cannot reach"):
        client(dead.url).scan("x")
    def slow_reply(seen):
        time.sleep(1.0)
        return 200, {}, {}

    slow = gw(slow_reply)
    with pytest.raises(SentinelUnavailableError, match="timed out"):
        client(slow.url, timeout=0.2).scan("x")
    with pytest.raises(SentinelUnavailableError):
        client(gw(ok("<html>oops</html>")).url).scan("x")


# ---------------------------------------------------------------- credential safety
@pytest.mark.parametrize("code", [301, 302, 303, 307, 308])
def test_never_follows_redirects_and_never_forwards_the_key(gw, code):
    target = gw(ok(CHAT_OK))
    evil = gw(lambda seen: (code, b"", {"location": f"{target.url}/steal"}))
    with pytest.raises(SentinelUnavailableError, match="redirect"):
        client(evil.url).secure(provider="gemini", prompt="x")
    assert target.seen == []           # the redirect target never received a request, let alone the key


@pytest.mark.parametrize("bad", ["", "snl_short", "sk-1234", KEY + "x", KEY.replace("snl_", "xxx_")])
def test_invalid_key_is_rejected_without_echo(bad, monkeypatch):
    monkeypatch.delenv("SENTINEL_API_KEY", raising=False)
    with pytest.raises(SentinelConfigError) as ei:
        Sentinel(api_key=bad, base_url="https://gw.example.test")
    if bad:
        assert bad not in str(ei.value)


def test_base_url_rules():
    with pytest.raises(SentinelConfigError, match="https"):
        Sentinel(api_key=KEY, base_url="http://gw.example.test")
    for bad in ("ftp://gw.example.test", "https://user:pw@gw.example.test", "not a url", "https://"):
        with pytest.raises(SentinelConfigError):
            Sentinel(api_key=KEY, base_url=bad)
    for good in ("https://gw.example.test", "http://localhost:4000", "http://127.0.0.1:4000"):
        Sentinel(api_key=KEY, base_url=good)
    Sentinel(api_key=KEY, base_url="http://10.0.0.5", allow_insecure_http=True)
    with pytest.raises(SentinelConfigError):
        Sentinel(api_key=KEY, base_url="https://gw.example.test", timeout=0)


def test_reads_environment_variables(gw, monkeypatch):
    g = gw(ok(CHAT_OK))
    monkeypatch.setenv("SENTINEL_API_KEY", KEY)
    monkeypatch.setenv("SENTINEL_BASE_URL", g.url)
    Sentinel().secure(provider="gemini", prompt="x")
    assert len(g.seen) == 1
    monkeypatch.delenv("SENTINEL_API_KEY")
    with pytest.raises(SentinelConfigError):
        Sentinel()


def test_key_never_appears_in_repr_or_pickle_or_traceback_text():
    c = Sentinel(api_key=KEY, base_url="https://gw.example.test")
    assert KEY not in repr(c) and KEY not in str(c) and "A" * 43 not in repr(c)
    with pytest.raises(TypeError):
        pickle.dumps(c)


def test_base_url_path_prefix_and_trailing_slashes(gw):
    g = gw(ok(CHAT_OK))
    Sentinel(api_key=KEY, base_url=f"{g.url}/gateway//").secure(provider="gemini", prompt="x")
    assert g.seen[0]["path"] == "/gateway/v1/ai/chat"


# ---------------------------------------------------------------- scan_file
FILE_OK = {"event_id": "f1", "decision": "REDACT", "failed_closed": False, "reason": None, "sanitized_text": "name: [REDACTED]",
           "file": {"sha256": "a" * 64, "size": 12, "detected_type": "txt", "mime": "text/plain", "pages": None, "ocr_used": False},
           "findings": [{"type": "hidden_text", "severity": "MEDIUM", "detail": "vanish run"}],
           "risk": {"risk_score": 45, "risk_level": "MEDIUM"},
           "detections": [{"entity": "EMAIL", "confidence": 0.9, "severity": "MEDIUM", "location": {"start": 6, "end": 9}, "detector": "pii"}],
           "policy_id": "p"}
FILE_BLOCKED = {**FILE_OK, "decision": "BLOCK", "reason": "macros_present", "sanitized_text": None, "detections": [],
                "findings": [{"type": "macros", "severity": "CRITICAL", "detail": "vbaProject.bin"}]}


def test_scan_file_sends_exact_bytes_with_only_a_synthetic_extension(gw):
    g = gw(ok(FILE_OK))
    data = bytes([0x25, 0x50, 0x44, 0x46, 0x00, 0xFF, 0xFE, 0x80])
    r = client(g.url).scan_file(data, "Q3 board minutes - CONFIDENTIAL.PDF", application="app", team="t", environment="prod")
    s = g.seen[0]
    assert s["path"] == "/v1/files/scan" and s["method"] == "POST"
    assert s["raw"] == data
    assert s["headers"]["content-type"] == "application/octet-stream"
    assert s["headers"]["authorization"] == f"Bearer {KEY}"
    assert unquote(s["headers"]["x-filename"]) == "upload.PDF" and "CONFIDENTIAL" not in s["headers"]["x-filename"]
    assert (s["headers"]["x-application"], s["headers"]["x-team"], s["headers"]["x-environment"]) == ("app", "t", "prod")
    assert (r.decision, r.blocked, r.failed_closed, r.reason, r.sanitized_text) == ("REDACT", False, False, None, "name: [REDACTED]")
    assert (r.risk_score, r.risk_level, r.policy_id, r.event_id) == (45, "MEDIUM", "p", "f1")
    assert (r.file.sha256, r.file.size, r.file.detected_type, r.file.mime, r.file.pages, r.file.ocr_used) == ("a" * 64, 12, "txt", "text/plain", None, False)
    assert (r.findings[0].type, r.findings[0].severity) == ("hidden_text", "MEDIUM")
    assert (r.detections[0].entity, r.detections[0].start, r.detections[0].end) == ("EMAIL", 6, 9)


def test_scan_file_omits_filename_header_without_an_extension_and_accepts_bytearray(gw):
    g = gw(ok(FILE_OK))
    client(g.url).scan_file(bytearray(b"hello"), "no-extension")
    assert g.seen[0]["raw"] == b"hello" and "x-filename" not in g.seen[0]["headers"]


def test_scan_file_rejects_non_bytes(gw):
    g = gw(ok(FILE_OK))
    with pytest.raises(SentinelConfigError):
        client(g.url).scan_file("just a string")
    assert g.seen == []


def test_blocked_file_is_returned_not_raised_with_reason_and_no_text(gw):
    g = gw(ok(FILE_BLOCKED))
    r = client(g.url).scan_file(b"x", "a.docx")
    assert (r.decision, r.blocked, r.reason, r.sanitized_text) == ("BLOCK", True, "macros_present", None)


@pytest.mark.parametrize("bad", [
    {**FILE_BLOCKED, "sanitized_text": "leak"}, {**FILE_OK, "sanitized_text": None}, {**FILE_OK, "file": None},
    {**FILE_OK, "findings": None}, {**FILE_OK, "risk": None}, {**FILE_OK, "decision": 5},
])
def test_scan_file_rejects_inconsistent_or_incomplete_results(gw, bad):
    g = gw(ok(bad))
    with pytest.raises(SentinelError):
        client(g.url).scan_file(b"x")


@pytest.mark.parametrize("status,cls", [(413, SentinelValidationError), (429, SentinelRateLimitError), (503, SentinelUnavailableError)])
def test_scan_file_gateway_errors_fail_closed(gw, status, cls):
    g = gw(ok({"error": "x"}, status=status))
    with pytest.raises(cls):
        client(g.url).scan_file(b"x")


@pytest.mark.parametrize("code", [301, 302, 303, 307, 308])
def test_scan_file_never_follows_redirects(gw, code):
    target = gw(ok(FILE_OK))
    g = gw(lambda seen: (code, b"", {"location": f"{target.url}/steal"}))
    with pytest.raises(SentinelError):
        client(g.url).scan_file(b"secret-file-bytes")
    assert target.seen == []
