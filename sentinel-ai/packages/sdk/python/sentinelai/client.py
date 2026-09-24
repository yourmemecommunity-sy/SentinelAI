"""Synchronous SentinelAI client (standard library only).

Fails closed everywhere: content is returned only when the gateway answered 200 with a well-formed body; every other
outcome (blocked, network failure, timeout, malformed reply) raises.
"""
from __future__ import annotations

import json
import os
import re
import socket
import ssl
import urllib.error
import urllib.request
from typing import TYPE_CHECKING, Any, Dict, Iterator, List, Mapping, Optional, Sequence, Union
from urllib.parse import quote, urlsplit

if TYPE_CHECKING:
    from email.message import Message

from . import __version__
from .errors import (
    SentinelAuthenticationError, SentinelBlockedError, SentinelConfigError, SentinelError, SentinelPermissionError,
    SentinelProviderError, SentinelRateLimitError, SentinelUnavailableError, SentinelValidationError,
)
from .types import (
    CheckResult, Detection, FileFinding, FileInfo, FileScanResult, RiskFactor, ScanResult, Security, SecureResponse, StageSummary,
    StreamSummary,
)

_KEY_FORMAT = re.compile(r"^snl_[A-Za-z0-9_-]{8}_[A-Za-z0-9_-]{43}$")
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}
_MAX_RESPONSE_BYTES = 10 * 1024 * 1024


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """urllib re-sends custom headers on redirect, which would hand our API key to another host. Never follow."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:  # noqa: D401
        return None


def _str(value: Any, what: str) -> str:
    if not isinstance(value, str):
        raise SentinelError(f"unexpected response: {what}")
    return value


class Sentinel:
    """Client for the SentinelAI security gateway.

    >>> client = Sentinel(api_key=os.getenv("SENTINEL_API_KEY"), base_url="https://gateway.example.com")
    >>> response = client.secure(provider="gemini", prompt="Summarize this ticket")
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        timeout: float = 60.0,
        allow_insecure_http: bool = False,
    ) -> None:
        key = api_key or os.environ.get("SENTINEL_API_KEY")
        if not key:
            raise SentinelConfigError("api_key is required (or set SENTINEL_API_KEY)")
        if not _KEY_FORMAT.match(key):
            raise SentinelConfigError("api_key is not a valid SentinelAI API key")  # never echo the value
        raw = base_url or os.environ.get("SENTINEL_BASE_URL")
        if not raw:
            raise SentinelConfigError("base_url is required (or set SENTINEL_BASE_URL)")
        try:
            parts = urlsplit(raw)
            host = parts.hostname
        except ValueError:
            raise SentinelConfigError("base_url is not a valid URL") from None
        if parts.scheme not in ("http", "https") or not host:
            raise SentinelConfigError("base_url must be http(s)")
        if parts.username or parts.password:
            raise SentinelConfigError("base_url must not contain credentials")
        if parts.scheme == "http" and host not in _LOCAL_HOSTS and not allow_insecure_http:
            raise SentinelConfigError(
                "base_url must use https:// (the API key would be sent in clear text). "
                "Set allow_insecure_http only for trusted networks."
            )
        if not timeout > 0:
            raise SentinelConfigError("timeout must be positive")

        self._api_key = key
        self._base = f"{parts.scheme}://{parts.netloc}{parts.path.rstrip('/')}"
        self._timeout = timeout
        self._opener = urllib.request.build_opener(
            _NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context())
        )

    def __repr__(self) -> str:  # keeps the key out of logs / tracebacks / debuggers
        return f"Sentinel(base_url={self._base!r}, api_key='[redacted]')"

    def __reduce__(self) -> Any:  # pickling would serialise the key
        raise TypeError("Sentinel clients cannot be pickled")

    # ------------------------------------------------------------------ public API
    def secure(
        self, provider: str, prompt: str, *, system: Optional[str] = None, model: Optional[str] = None,
        application: Optional[str] = None, team: Optional[str] = None, environment: Optional[str] = None,
        max_output_tokens: Optional[int] = None, temperature: Optional[float] = None, timeout: Optional[float] = None,
    ) -> SecureResponse:
        """Send a prompt to an AI provider through SentinelAI. Raises SentinelBlockedError if security blocks it."""
        messages: List[Dict[str, str]] = ([{"role": "system", "content": system}] if system else []) + [
            {"role": "user", "content": prompt}
        ]
        return self.chat(
            provider, messages, model=model, application=application, team=team, environment=environment,
            max_output_tokens=max_output_tokens, temperature=temperature, timeout=timeout,
        )

    def chat(
        self, provider: str, messages: Sequence[Mapping[str, str]], *, model: Optional[str] = None,
        application: Optional[str] = None, team: Optional[str] = None, environment: Optional[str] = None,
        max_output_tokens: Optional[int] = None, temperature: Optional[float] = None, timeout: Optional[float] = None,
        session_id: Optional[str] = None, hydrate: Optional[bool] = None,
    ) -> SecureResponse:
        """`session_id` names a token-vault session (scoped to your API key by the gateway): values your policy TOKENIZEs
        keep one token across calls with the same id, and the reply comes back with them restored."""
        payload = _chat_payload(provider, messages, model, application, team, environment, max_output_tokens, temperature, session_id, hydrate)
        body = self._post("/v1/ai/chat", payload, timeout)
        sec = body.get("security")
        if not isinstance(sec, dict) or not isinstance(sec.get("input"), dict) or not isinstance(sec.get("output"), dict):
            raise SentinelError("unexpected response: security summary missing")
        hyd = body.get("hydration")
        return SecureResponse(
            content=_str(body.get("content"), "content"), provider=_str(body.get("provider"), "provider"),
            model=_str(body.get("model"), "model"), security=Security(_stage(sec["input"]), _stage(sec["output"])),
            hydration=hyd if hyd in ("applied", "degraded") else None,
        )

    def stream(
        self, provider: str, messages: Sequence[Mapping[str, str]], *, model: Optional[str] = None,
        application: Optional[str] = None, team: Optional[str] = None, environment: Optional[str] = None,
        max_output_tokens: Optional[int] = None, temperature: Optional[float] = None, session_id: Optional[str] = None,
        hydrate: Optional[bool] = None, mode: Optional[str] = None, idle_timeout: Optional[float] = None,
    ) -> "SecureStream":
        """Stream a reply through SentinelAI. Iterate for text as it is released; `.summary` is set when it completes.

            with client.stream("gemini", messages) as s:
                for text in s:
                    print(text, end="")
            print(s.summary.security.output.decision)

        Fail-closed contract: a stream is complete ONLY when it ends with the gateway's `done` event. A block, provider
        failure, idle timeout, or a connection that drops mid-reply raises from the iterator, even though text already
        yielded was scanned before release. Treat any exception as "the reply is incomplete".
        `idle_timeout` (default: the client timeout) bounds the gap between events, not the whole stream.
        """
        if mode is not None and mode not in ("holdback", "buffered"):
            raise SentinelConfigError('mode must be "holdback" or "buffered"')
        payload = _chat_payload(provider, messages, model, application, team, environment, max_output_tokens, temperature, session_id, hydrate)
        if mode:
            payload["mode"] = mode
        return SecureStream(self, payload, idle_timeout or self._timeout)

    def _open_stream(self, payload: Dict[str, Any], idle_timeout: float) -> Any:
        req = urllib.request.Request(
            f"{self._base}/v1/ai/stream", data=json.dumps(payload).encode(), method="POST",
            headers={
                "content-type": "application/json", "accept": "text/event-stream",
                "authorization": f"Bearer {self._api_key}", "user-agent": f"sentinelai-python/{__version__}",
            },
        )
        try:
            resp = self._opener.open(req, timeout=idle_timeout)
        except urllib.error.HTTPError as e:
            status, headers = e.code, e.headers
            try:
                raw = e.read(_MAX_RESPONSE_BYTES + 1)
            except Exception:  # noqa: BLE001
                raw = b""
            if 300 <= status < 400:
                raise SentinelUnavailableError("gateway attempted a redirect; refusing to follow it", status) from None
            try:
                parsed = json.loads(raw.decode("utf-8")) if raw else None
            except (ValueError, UnicodeDecodeError):
                parsed = None
            _raise_for(status, headers, parsed if isinstance(parsed, dict) else {})
        except (socket.timeout, TimeoutError):
            raise SentinelUnavailableError("request timed out") from None
        except urllib.error.URLError as e:
            if isinstance(e.reason, (socket.timeout, TimeoutError)):
                raise SentinelUnavailableError("request timed out") from None
            raise SentinelUnavailableError("cannot reach the SentinelAI gateway") from None
        except (OSError, ssl.SSLError):
            raise SentinelUnavailableError("cannot reach the SentinelAI gateway") from None
        if not str(resp.headers.get("content-type", "")).startswith("text/event-stream"):
            resp.close()
            raise SentinelUnavailableError("gateway returned an unusable response", resp.status)
        return resp

    def scan(
        self, text: str, direction: str = "INPUT", *, application: Optional[str] = None, team: Optional[str] = None,
        environment: Optional[str] = None, timeout: Optional[float] = None,
    ) -> ScanResult:
        """Scan text without calling a model. A blocked result is returned, not raised."""
        payload: Dict[str, Any] = {"text": text, "direction": direction}
        ctx = _ctx(application, team, environment)
        if ctx:
            payload["context"] = ctx
        b = self._post("/v1/security/scan", payload, timeout)
        risk = b.get("risk")
        if not isinstance(risk, dict) or not isinstance(b.get("detections"), list) or not isinstance(risk.get("factors"), list):
            raise SentinelError("unexpected response: evidence missing")
        decision = _str(b.get("decision"), "decision")
        blocked = decision in ("BLOCK", "QUARANTINE")
        sanitized = b.get("sanitized_text")
        # Invariant: a blocked decision never carries text and a non-blocked one always does; anything else is untrustworthy.
        if (sanitized is not None) if blocked else (not isinstance(sanitized, str)):
            raise SentinelError("unexpected response: inconsistent decision")
        return ScanResult(
            request_id=_str(b.get("request_id"), "request_id"), event_id=b.get("event_id") if isinstance(b.get("event_id"), str) else None,
            decision=decision, blocked=blocked, failed_closed=b.get("failed_closed") is True,
            fail_closed_reason=b.get("fail_closed_reason") if isinstance(b.get("fail_closed_reason"), str) else None,
            risk_score=int(risk.get("risk_score", 0)), risk_level=_str(risk.get("risk_level"), "risk_level"),
            policy_id=_str(b.get("policy_id"), "policy_id"), sanitized_text=sanitized,
            detections=[
                Detection(_str(d.get("entity"), "entity"), float(d.get("confidence", 0)), _str(d.get("severity"), "severity"),
                          int((d.get("location") or {}).get("start", 0)), int((d.get("location") or {}).get("end", 0)), _str(d.get("detector"), "detector"))
                for d in b["detections"]
            ],
            risk_factors=[RiskFactor(_str(f.get("name"), "factor"), float(f.get("contribution", 0)), _str(f.get("detail"), "detail")) for f in risk["factors"]],
        )

    def check(
        self, text: str, direction: str = "INPUT", *, application: Optional[str] = None, team: Optional[str] = None,
        environment: Optional[str] = None, timeout: Optional[float] = None,
    ) -> CheckResult:
        """Cheap allow/deny check. `allowed` is True only for an unmodified ALLOW decision."""
        payload: Dict[str, Any] = {"text": text, "direction": direction}
        ctx = _ctx(application, team, environment)
        if ctx:
            payload["context"] = ctx
        b = self._post("/v1/security/check", payload, timeout)
        decision = _str(b.get("decision"), "decision")
        return CheckResult(
            allowed=b.get("allowed") is True and decision == "ALLOW", decision=decision,
            risk_level=_str(b.get("risk_level"), "risk_level"), failed_closed=b.get("failed_closed") is True,
            event_id=b.get("event_id") if isinstance(b.get("event_id"), str) else None,
        )

    def scan_file(
        self, data: bytes, filename: Optional[str] = None, *, application: Optional[str] = None, team: Optional[str] = None,
        environment: Optional[str] = None, timeout: Optional[float] = None,
    ) -> FileScanResult:
        """Scan a file (PDF, DOCX, XLSX, CSV, TXT, JSON, PNG/JPEG/GIF/WEBP) before it goes anywhere near a model.

        A blocked file is RETURNED (`result.blocked`), never raised, so callers must check it. Network failure, timeout
        or an unusable reply raises. Only the file extension is sent; the name itself never leaves your process.
        """
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise SentinelConfigError("data must be bytes")
        m = re.search(r"\.[A-Za-z0-9]{1,8}$", filename or "")
        headers: Dict[str, str] = {}
        if m:
            headers["x-filename"] = quote(f"upload{m.group(0)}")
        for h, v in (("x-application", application), ("x-team", team), ("x-environment", environment)):
            if v:
                headers[h] = v
        b = self._request("/v1/files/scan", bytes(data), "application/octet-stream", headers, timeout)
        risk, file = b.get("risk"), b.get("file")
        if not isinstance(risk, dict) or not isinstance(file, dict) or not isinstance(b.get("findings"), list) or not isinstance(b.get("detections"), list):
            raise SentinelError("unexpected response: file scan evidence missing")
        decision = _str(b.get("decision"), "decision")
        blocked = decision in ("BLOCK", "QUARANTINE")
        sanitized = b.get("sanitized_text")
        if (sanitized is not None) if blocked else (not isinstance(sanitized, str)):
            raise SentinelError("unexpected response: inconsistent decision")
        return FileScanResult(
            event_id=b.get("event_id") if isinstance(b.get("event_id"), str) else None, decision=decision, blocked=blocked,
            failed_closed=b.get("failed_closed") is True, reason=b.get("reason") if isinstance(b.get("reason"), str) else None,
            file=FileInfo(_str(file.get("sha256"), "sha256"), int(file.get("size", 0)), file.get("detected_type") if isinstance(file.get("detected_type"), str) else None,
                          file.get("mime") if isinstance(file.get("mime"), str) else None, file.get("pages") if isinstance(file.get("pages"), int) else None, file.get("ocr_used") is True),
            risk_score=int(risk.get("risk_score", 0)), risk_level=_str(risk.get("risk_level"), "risk_level"), policy_id=_str(b.get("policy_id"), "policy_id"),
            sanitized_text=sanitized,
            findings=[FileFinding(_str(f.get("type"), "finding"), _str(f.get("severity"), "severity"), _str(f.get("detail"), "detail")) for f in b["findings"]],
            detections=[Detection(_str(d.get("entity"), "entity"), float(d.get("confidence", 0)), _str(d.get("severity"), "severity"),
                                  int((d.get("location") or {}).get("start", 0)), int((d.get("location") or {}).get("end", 0)), _str(d.get("detector"), "detector")) for d in b["detections"]],
        )

    # ------------------------------------------------------------------ transport
    def _post(self, path: str, payload: Dict[str, Any], timeout: Optional[float]) -> Dict[str, Any]:
        return self._request(path, json.dumps(payload).encode(), "application/json", {}, timeout)

    def _request(self, path: str, body: bytes, content_type: str, extra_headers: Dict[str, str], timeout: Optional[float]) -> Dict[str, Any]:
        req = urllib.request.Request(
            f"{self._base}{path}", data=body, method="POST",
            headers={
                "content-type": content_type, "accept": "application/json",
                "authorization": f"Bearer {self._api_key}", "user-agent": f"sentinelai-python/{__version__}", **extra_headers,
            },
        )
        status = 0
        headers: Union[Mapping[str, str], Message] = {}
        raw = b""
        try:
            with self._opener.open(req, timeout=timeout or self._timeout) as resp:
                status, headers, raw = resp.status, resp.headers, resp.read(_MAX_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as e:
            status, headers = e.code, e.headers
            try:
                raw = e.read(_MAX_RESPONSE_BYTES + 1)
            except Exception:  # noqa: BLE001
                raw = b""
            if 300 <= status < 400:
                raise SentinelUnavailableError("gateway attempted a redirect; refusing to follow it", status) from None
        except (socket.timeout, TimeoutError):
            raise SentinelUnavailableError("request timed out") from None
        except urllib.error.URLError as e:
            if isinstance(e.reason, (socket.timeout, TimeoutError)):
                raise SentinelUnavailableError("request timed out") from None
            raise SentinelUnavailableError("cannot reach the SentinelAI gateway") from None
        except (OSError, ssl.SSLError):
            raise SentinelUnavailableError("cannot reach the SentinelAI gateway") from None

        if len(raw) > _MAX_RESPONSE_BYTES:
            raise SentinelUnavailableError("gateway response too large", status)
        try:
            parsed = json.loads(raw.decode("utf-8")) if raw else None
        except (ValueError, UnicodeDecodeError):
            parsed = None
        obj: Dict[str, Any] = parsed if isinstance(parsed, dict) else {}

        if 200 <= status < 300:
            if not isinstance(parsed, dict):
                raise SentinelUnavailableError("gateway returned an unusable response", status)
            return parsed
        _raise_for(status, headers, obj)
        raise AssertionError("unreachable")  # _raise_for always raises


def _raise_for(status: int, headers: Any, obj: Dict[str, Any]) -> None:
    """Maps a non-2xx gateway response to a typed error. Shared by every call so streaming fails closed exactly like chat."""
    if status == 401:
        raise SentinelAuthenticationError("authentication failed: check your API key", 401, "unauthorized")
    if status == 403:
        if obj.get("error") == "blocked":
            raise SentinelBlockedError(
                "output" if obj.get("stage") == "output" else "input",
                obj["decision"] if isinstance(obj.get("decision"), str) else "BLOCK", obj.get("failed_closed") is True,
                obj["reason"] if isinstance(obj.get("reason"), str) else None,
                obj["event_id"] if isinstance(obj.get("event_id"), str) else None,
            )
        raise SentinelPermissionError("this API key is not permitted to use this endpoint", 403, "forbidden")
    if status == 413:
        raise SentinelValidationError("request too large", 413)
    if status == 422:
        issues = [{"path": str(i.get("path", "")), "message": str(i.get("message", ""))} for i in obj.get("issues", []) if isinstance(i, dict)] if isinstance(obj.get("issues"), list) else []
        raise SentinelValidationError("request rejected as invalid", 422, issues)
    if status == 429:
        try:
            ra: Optional[float] = float(headers.get("retry-after", "")) if headers else None
        except (TypeError, ValueError):
            ra = None
        raise SentinelRateLimitError(ra if ra and ra > 0 else None)
    if status == 502:
        raise SentinelProviderError(obj["code"] if isinstance(obj.get("code"), str) else "unknown", obj["event_id"] if isinstance(obj.get("event_id"), str) else None)
    if status >= 500:
        raise SentinelUnavailableError(f"gateway unavailable (HTTP {status})", status, obj["error"] if isinstance(obj.get("error"), str) else None)
    raise SentinelError(f"unexpected HTTP {status}", status)


def _stage(s: Dict[str, Any]) -> StageSummary:
    return StageSummary(_str(s.get("decision"), "decision"), _str(s.get("risk_level"), "risk_level"), _str(s.get("event_id"), "event_id"))


def _chat_payload(
    provider: str, messages: Sequence[Mapping[str, str]], model: Optional[str], application: Optional[str], team: Optional[str],
    environment: Optional[str], max_output_tokens: Optional[int], temperature: Optional[float], session_id: Optional[str],
    hydrate: Optional[bool],
) -> Dict[str, Any]:
    payload: Dict[str, Any] = {"provider": provider, "messages": [dict(m) for m in messages]}
    if model:
        payload["model"] = model
    if max_output_tokens is not None:
        payload["max_output_tokens"] = max_output_tokens
    if temperature is not None:
        payload["temperature"] = temperature
    if session_id is not None:
        payload["session_id"] = session_id
    if hydrate is not None:
        payload["hydrate"] = hydrate
    payload.update(_ctx(application, team, environment))
    return payload


_MAX_EVENT_BYTES = 1_000_000


class SecureStream:
    """One streamed reply. Iterable over text; single use. Also a context manager that always closes the connection."""

    def __init__(self, client: "Sentinel", payload: Dict[str, Any], idle_timeout: float) -> None:
        self._client, self._payload, self._idle = client, payload, idle_timeout
        self._resp: Any = None
        self._started = False
        self.summary: Optional[StreamSummary] = None

    def __enter__(self) -> "SecureStream":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def close(self) -> None:
        """Stops the stream; closing the connection makes the gateway abort the upstream provider request."""
        if self._resp is not None:
            try:
                self._resp.close()
            finally:
                self._resp = None

    def text(self) -> str:
        """The whole reply as one string. Still fails closed: raises unless the stream completed."""
        return "".join(self)

    def __iter__(self) -> Iterator[str]:
        if self._started:
            raise SentinelError("a stream can only be iterated once")
        self._started = True
        return self._events()

    def _events(self) -> Iterator[str]:
        try:
            self._resp = self._client._open_stream(self._payload, self._idle)
            event, size = "message", 0
            data: List[str] = []
            while True:
                try:
                    raw = self._resp.readline(_MAX_EVENT_BYTES + 1)
                except (socket.timeout, TimeoutError):
                    raise SentinelUnavailableError("stream stalled: no data from the gateway") from None
                except (OSError, ValueError, AttributeError):
                    raise SentinelUnavailableError("stream ended before the gateway completed it") from None
                if not raw:
                    # EOF without `done`: whatever was yielded is NOT a complete reply.
                    raise SentinelUnavailableError("stream ended before the gateway completed it")
                size += len(raw)
                if size > _MAX_EVENT_BYTES:
                    raise SentinelUnavailableError("gateway sent an oversized stream event")
                line = raw.decode("utf-8").rstrip("\r\n")
                if line == "":
                    if data:
                        ev = _parse_event(event, data)
                        if ev[0] == "delta":
                            text = ev[1].get("text")
                            if not isinstance(text, str):
                                raise SentinelError("unexpected response: malformed delta")
                            if text:
                                yield text
                        elif ev[0] == "done":
                            self.summary = _summary(ev[1])
                            return
                        elif ev[0] == "error":
                            raise _stream_error(ev[1])
                    event, data, size = "message", [], 0
                    continue
                if line.startswith(":"):
                    continue
                field, _, value = line.partition(":")
                value = value[1:] if value.startswith(" ") else value
                if field == "event":
                    event = value
                elif field == "data":
                    data.append(value)
        finally:
            self.close()


def _parse_event(event: str, data: List[str]) -> "tuple[str, Dict[str, Any]]":
    try:
        obj = json.loads("\n".join(data))
    except ValueError:
        raise SentinelError("unexpected response: stream event is not JSON") from None
    if not isinstance(obj, dict):
        raise SentinelError("unexpected response: stream event is not an object")
    return event, obj


def _summary(d: Dict[str, Any]) -> StreamSummary:
    sec = d.get("security")
    if not isinstance(sec, dict) or not isinstance(sec.get("input"), dict) or not isinstance(sec.get("output"), dict):
        raise SentinelError("unexpected response: malformed summary")
    hyd = d.get("hydration")
    return StreamSummary(
        provider=_str(d.get("provider"), "provider"), model=_str(d.get("model"), "model"),
        hydration=hyd if hyd in ("applied", "degraded") else "off", security=Security(_stage(sec["input"]), _stage(sec["output"])),
    )


def _stream_error(d: Dict[str, Any]) -> SentinelError:
    event_id = d["event_id"] if isinstance(d.get("event_id"), str) else None
    if d.get("error") == "blocked":
        return SentinelBlockedError(
            "input" if d.get("stage") == "input" else "output", d["decision"] if isinstance(d.get("decision"), str) else "BLOCK",
            d.get("failed_closed") is True, d["reason"] if isinstance(d.get("reason"), str) else None, event_id,
        )
    if d.get("error") == "provider_error":
        return SentinelProviderError(d["code"] if isinstance(d.get("code"), str) else "unknown", event_id)
    err = d.get("error") if isinstance(d.get("error"), str) else "error"
    return SentinelUnavailableError(f"stream ended by the gateway: {err}", 200, err)


def _ctx(application: Optional[str], team: Optional[str], environment: Optional[str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if application:
        out["application"] = application
    if team:
        out["team"] = team
    if environment:
        out["environment"] = environment
    return out
