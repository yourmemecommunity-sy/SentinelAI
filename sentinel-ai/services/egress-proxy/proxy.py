"""Allow-list egress proxy for the security engine's AI judge.

The engine lives on an internal network with no internet access. The only outbound connection it may make is HTTPS to
the judge's API. This proxy accepts HTTP CONNECT requests and tunnels them ONLY to hosts:ports in EGRESS_ALLOW
(default "api.anthropic.com:443"); everything else gets 403 and is logged. It never sees plaintext: TLS is end-to-end
between the engine and the API, so the proxy cannot read or log request content.

Plain HTTP (non-CONNECT) requests are refused: a judge call is always TLS.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import time

ALLOW = {h.strip().lower() for h in os.environ.get("EGRESS_ALLOW", "api.anthropic.com:443").split(",") if h.strip()}
PORT = int(os.environ.get("EGRESS_PORT", "8899"))
MAX_TUNNELS = int(os.environ.get("EGRESS_MAX_TUNNELS", "64"))
IDLE_S = float(os.environ.get("EGRESS_IDLE_S", "60"))
_active = 0


def log(event: str, **fields: object) -> None:
    print(json.dumps({"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "event": event, **fields}), flush=True)


def allowed(target: str) -> bool:
    return target.lower() in ALLOW


async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> int:
    total = 0
    try:
        while True:
            chunk = await asyncio.wait_for(reader.read(65536), timeout=IDLE_S)
            if not chunk:
                break
            total += len(chunk)
            writer.write(chunk)
            await writer.drain()
    except (asyncio.TimeoutError, ConnectionError, OSError):
        pass
    finally:
        try:
            writer.close()
        except OSError:
            pass
    return total


async def handle(client_r: asyncio.StreamReader, client_w: asyncio.StreamWriter) -> None:
    global _active
    peer = client_w.get_extra_info("peername")
    try:
        head = await asyncio.wait_for(client_r.readuntil(b"\r\n\r\n"), timeout=10)
    except (asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError, ConnectionError):
        client_w.close()
        return
    line = head.split(b"\r\n", 1)[0].decode("latin-1")
    parts = line.split()
    if len(parts) != 3 or parts[0] != "CONNECT":
        log("refused", reason="not_connect", peer=str(peer))
        client_w.write(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        await client_w.drain()
        client_w.close()
        return
    target = parts[1]
    if not allowed(target) or _active >= MAX_TUNNELS:
        log("refused", reason="not_allowed" if not allowed(target) else "too_many_tunnels", target=target)
        client_w.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        await client_w.drain()
        client_w.close()
        return
    host, _, port = target.rpartition(":")
    try:
        up_r, up_w = await asyncio.wait_for(asyncio.open_connection(host, int(port)), timeout=10)
    except (OSError, asyncio.TimeoutError, ValueError):
        log("upstream_unreachable", target=target)
        client_w.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        await client_w.drain()
        client_w.close()
        return
    _active += 1
    started = time.monotonic()
    client_w.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
    await client_w.drain()
    sent, received = await asyncio.gather(_pipe(client_r, up_w), _pipe(up_r, client_w))
    _active -= 1
    log("tunnel_closed", target=target, bytes_out=sent, bytes_in=received, seconds=round(time.monotonic() - started, 2))


async def main() -> None:
    server = await asyncio.start_server(handle, "0.0.0.0", PORT)  # noqa: S104 - container-internal listener
    log("listening", port=PORT, allow=sorted(ALLOW))
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "healthcheck":
        import socket
        with socket.create_connection(("127.0.0.1", PORT), timeout=3):
            pass
        sys.exit(0)
    asyncio.run(main())
