import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from sentinelai import (
    Sentinel, SentinelAuthenticationError, SentinelBlockedError, SentinelError, SentinelProviderError, SentinelRateLimitError,
    SentinelUnavailableError,
)

KEY = "snl_" + "abcd1234" + "_" + "A" * 43          # shaped like a key, not a real credential
DONE = {"provider": "gemini", "model": "m1", "hydration": "applied", "security": {
    "input": {"decision": "TOKENIZE", "risk_level": "LOW", "event_id": "e-in"},
    "output": {"decision": "ALLOW", "risk_level": "LOW", "event_id": "e-out"}}}
MSGS = [{"role": "user", "content": "hi"}]


def ev(event, data):
    return f"event: {event}\ndata: {json.dumps(data)}\n\n".encode()


class Server:
    """A real HTTP server. `handler(h)` writes the response using the BaseHTTPRequestHandler `h`."""

    def __init__(self, handler):
        self.requests: list[dict[str, object]] = []
        self.closed = threading.Event()
        outer = self

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("content-length", 0)))
                outer.requests.append({"path": self.path, "headers": {k.lower(): v for k, v in self.headers.items()}, "body": body})
                try:
                    handler(self)
                except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                    outer.closed.set()

            do_GET = do_POST

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.srv.daemon_threads = True
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def stop(self):
        self.srv.shutdown()
        self.srv.server_close()


@pytest.fixture
def serve():
    made = []

    def make(handler):
        s = Server(handler)
        made.append(s)
        return s

    yield make
    for s in made:
        s.stop()


def sse_head(h, chunked=True):
    h.send_response(200)
    h.send_header("content-type", "text/event-stream; charset=utf-8")
    if chunked:
        h.send_header("transfer-encoding", "chunked")
    h.end_headers()


def chunk(h, data: bytes):
    h.wfile.write(f"{len(data):x}\r\n".encode() + data + b"\r\n")
    h.wfile.flush()


def finish(h):
    h.wfile.write(b"0\r\n\r\n")
    h.wfile.flush()


def client(url, **kw):
    return Sentinel(api_key=KEY, base_url=url, **kw)


# ---------------------------------------------------------------- happy path
def test_yields_deltas_and_sets_the_summary_and_sends_the_right_request(serve):
    def h(x):
        sse_head(x)
        chunk(x, ev("delta", {"text": "Hello "}))
        chunk(x, ev("delta", {"text": "world"}))
        chunk(x, ev("done", DONE))
        finish(x)

    s = serve(h)
    st = client(s.url).stream("gemini", MSGS, session_id="conv-1", hydrate=True, mode="buffered", model="m1")
    assert list(st) == ["Hello ", "world"]
    assert st.summary.provider == "gemini" and st.summary.hydration == "applied"
    assert st.summary.security.input.decision == "TOKENIZE" and st.summary.security.output.event_id == "e-out"
    r = s.requests[0]
    assert r["path"] == "/v1/ai/stream"
    assert r["headers"]["authorization"] == f"Bearer {KEY}" and r["headers"]["accept"] == "text/event-stream"
    body = json.loads(r["body"])
    assert body == {"provider": "gemini", "model": "m1", "messages": MSGS, "session_id": "conv-1", "hydrate": True, "mode": "buffered"}


def test_events_split_across_network_chunks_heartbeats_and_crlf(serve):
    payload = b": ping\n\n" + ev("delta", {"text": "a\nb"}) + b"event: delta\r\ndata: {\"text\": \"\\u00e7\"}\r\n\r\n" + ev("done", DONE)

    def h(x):
        sse_head(x)
        for i in range(len(payload)):
            chunk(x, payload[i:i + 1])
        finish(x)

    assert client(serve(h).url).stream("gemini", MSGS).text() == "a\nbç"


# ---------------------------------------------------------------- fail-closed
def test_blocked_output_raises_after_delivering_the_already_scanned_text(serve):
    def h(x):
        sse_head(x)
        chunk(x, ev("delta", {"text": "safe start "}))
        chunk(x, ev("error", {"error": "blocked", "stage": "output", "decision": "BLOCK", "failed_closed": False, "reason": None, "event_id": "e9"}))
        finish(x)

    st = client(serve(h).url).stream("gemini", MSGS)
    got = []
    with pytest.raises(SentinelBlockedError) as e:
        for t in st:
            got.append(t)
    assert got == ["safe start "]
    assert (e.value.stage, e.value.decision, e.value.event_id) == ("output", "BLOCK", "e9")
    assert st.summary is None


@pytest.mark.parametrize("how", ["clean-eof", "dropped-connection"])
def test_a_stream_that_ends_without_done_is_incomplete(serve, how):
    def h(x):
        sse_head(x)
        chunk(x, ev("delta", {"text": "partial"}))
        if how == "clean-eof":
            finish(x)
        else:
            x.connection.shutdown(2)

    st = client(serve(h).url).stream("gemini", MSGS)
    with pytest.raises(SentinelUnavailableError, match="before the gateway completed"):
        st.text()
    assert st.summary is None


@pytest.mark.parametrize("data,cls", [
    ({"error": "provider_error", "code": "rate_limit", "event_id": "e1"}, SentinelProviderError),
    ({"error": "idle_timeout"}, SentinelUnavailableError),
    ({"error": "audit_unavailable"}, SentinelUnavailableError),
])
def test_gateway_error_events_map_to_typed_errors(serve, data, cls):
    def h(x):
        sse_head(x)
        chunk(x, ev("error", data))
        finish(x)

    with pytest.raises(cls):
        client(serve(h).url).stream("gemini", MSGS).text()


@pytest.mark.parametrize("status,body,cls", [
    (403, {"error": "blocked", "stage": "input", "decision": "BLOCK", "failed_closed": True, "reason": "unknown_provider"}, SentinelBlockedError),
    (401, {"error": "unauthorized"}, SentinelAuthenticationError),
    (429, {"error": "too_many_streams"}, SentinelRateLimitError),
    (503, {"error": "audit_unavailable"}, SentinelUnavailableError),
])
def test_errors_before_the_stream_starts_map_exactly_like_chat(serve, status, body, cls):
    def h(x):
        raw = json.dumps(body).encode()
        x.send_response(status)
        x.send_header("content-type", "application/json")
        x.send_header("retry-after", "1")
        x.send_header("content-length", str(len(raw)))
        x.end_headers()
        x.wfile.write(raw)

    with pytest.raises(cls):
        client(serve(h).url).stream("gemini", MSGS).text()


def test_a_200_that_is_not_an_event_stream_is_refused(serve):
    def h(x):
        x.send_response(200)
        x.send_header("content-type", "application/json")
        x.send_header("content-length", "2")
        x.end_headers()
        x.wfile.write(b"{}")

    with pytest.raises(SentinelUnavailableError):
        client(serve(h).url).stream("gemini", MSGS).text()


@pytest.mark.parametrize("payload", [b"event: delta\ndata: not json\n\n", ev("delta", {"nope": 1}), ev("done", {"provider": "g", "model": "m"})])
def test_malformed_streams_are_refused(serve, payload):
    def h(x):
        sse_head(x)
        chunk(x, payload)
        finish(x)

    with pytest.raises(SentinelError):
        client(serve(h).url).stream("gemini", MSGS).text()


def test_a_stalled_gateway_trips_the_idle_timeout(serve):
    def h(x):
        sse_head(x)
        chunk(x, ev("delta", {"text": "x"}))
        time.sleep(3)

    t0 = time.monotonic()
    with pytest.raises(SentinelUnavailableError, match="stalled"):
        client(serve(h).url).stream("gemini", MSGS, idle_timeout=0.4).text()
    assert time.monotonic() - t0 < 2.5


@pytest.mark.parametrize("code", [301, 302, 307, 308])
def test_redirects_are_never_followed(serve, code):
    target = serve(lambda x: (sse_head(x), chunk(x, ev("done", DONE)), finish(x)))

    def h(x):
        x.send_response(code)
        x.send_header("location", f"{target.url}/v1/ai/stream")
        x.send_header("content-length", "0")
        x.end_headers()

    with pytest.raises(SentinelUnavailableError):
        client(serve(h).url).stream("gemini", MSGS).text()
    assert target.requests == []


def test_invalid_mode_is_rejected_before_any_request():
    with pytest.raises(Exception):
        client("http://127.0.0.1:9").stream("gemini", MSGS, mode="warp")


# ---------------------------------------------------------------- cancellation and single use
def test_closing_early_drops_the_connection_so_the_gateway_can_abort_upstream(serve):
    def h(x):
        sse_head(x)
        for i in range(2000):
            chunk(x, ev("delta", {"text": f"{i} "}))
            time.sleep(0.005)
        finish(x)

    s = serve(h)
    with client(s.url).stream("gemini", MSGS) as st:
        for n, _t in enumerate(st):
            if n == 3:
                break
    assert s.closed.wait(5), "server never saw the client hang up"


def test_a_stream_can_only_be_consumed_once(serve):
    s = serve(lambda x: (sse_head(x), chunk(x, ev("done", DONE)), finish(x)))
    st = client(s.url).stream("gemini", MSGS)
    st.text()
    with pytest.raises(SentinelError, match="only be iterated once"):
        st.text()


def test_chat_sends_session_options_and_surfaces_hydration(serve):
    def h(x):
        raw = json.dumps({"provider": "gemini", "model": "m1", "content": "hi", "hydration": "applied", "security": DONE["security"]}).encode()
        x.send_response(200)
        x.send_header("content-type", "application/json")
        x.send_header("content-length", str(len(raw)))
        x.end_headers()
        x.wfile.write(raw)

    s = serve(h)
    r = client(s.url).chat("gemini", MSGS, session_id="s1", hydrate=True)
    assert r.hydration == "applied"
    assert json.loads(s.requests[0]["body"])["session_id"] == "s1"
