"""Egress proxy: only allow-listed CONNECT targets are tunnelled; everything else is refused before any upstream contact."""
import asyncio
import importlib
import os

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # proxy.py lives one level up




async def _upstream():
    seen = []

    async def echo(r, w):
        seen.append(True)
        data = await r.read(100)
        w.write(b"echo:" + data)
        await w.drain()
        w.close()
    server = await asyncio.start_server(echo, "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1], seen


async def _ask(port: int, request: bytes, payload: bytes = b"") -> bytes:
    r, w = await asyncio.open_connection("127.0.0.1", port)
    w.write(request)
    await w.drain()
    head = await r.readuntil(b"\r\n\r\n")
    if payload and b" 200 " in head:
        w.write(payload)
        await w.drain()
        head += await r.read(100)
    w.close()
    return head


def test_allow_list_is_enforced(monkeypatch):
    async def scenario():
        up, up_port, seen = await _upstream()
        monkeypatch.setenv("EGRESS_ALLOW", f"127.0.0.1:{up_port}")
        import proxy as mod
        mod = importlib.reload(mod)
        srv = await asyncio.start_server(mod.handle, "127.0.0.1", 0)
        port = srv.sockets[0].getsockname()[1]
        ok = await _ask(port, f"CONNECT 127.0.0.1:{up_port} HTTP/1.1\r\nHost: x\r\n\r\n".encode(), b"hello")
        assert b"200 Connection Established" in ok and b"echo:hello" in ok
        assert len(seen) == 1
        for req in (b"CONNECT example.com:443 HTTP/1.1\r\n\r\n", b"CONNECT 169.254.169.254:80 HTTP/1.1\r\n\r\n",
                    f"CONNECT 127.0.0.1:{up_port + 1} HTTP/1.1\r\n\r\n".encode()):
            assert b"403" in await _ask(port, req)
        assert b"405" in await _ask(port, b"GET http://api.anthropic.com/ HTTP/1.1\r\n\r\n")
        assert len(seen) == 1  # no refused request ever reached an upstream
        srv.close(); up.close()
    asyncio.run(scenario())


def test_default_allow_list_is_only_the_anthropic_api(monkeypatch):
    monkeypatch.delenv("EGRESS_ALLOW", raising=False)
    import proxy as mod
    mod = importlib.reload(mod)
    assert mod.ALLOW == {"api.anthropic.com:443"}
    assert mod.allowed("API.ANTHROPIC.COM:443") and not mod.allowed("api.anthropic.com:80")
    assert not mod.allowed("api.anthropic.com.evil.test:443")
