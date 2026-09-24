#!/usr/bin/env python3
"""Circuit breaker + TTL of the token vault against a REAL Redis server that is made to fail on purpose.

The unit tests drive the breaker with injected failing clients; this drives it with a real Redis that is frozen
(`docker pause`) and resumed, and checks a real TTL on the server. Run inside the token-vault image with host
networking, pointing at a throwaway Redis container, e.g. (from WSL):

    docker run -d --name vault-breaker-redis -p 127.0.0.1:6390:6379 redis:7-alpine
    docker run --rm --network host -v "$PWD/scripts/development:/s:ro" -v /tmp/breaker-ctl:/ctl -e CTL_DIR=/ctl \
        -e PYTHONPATH=/srv -e REDIS_URL=redis://127.0.0.1:6390/0 sentinel-ai/token-vault:local python /s/vault-breaker-live.py

Pausing needs the Docker CLI, which the vault image does not have, so the script asks its caller to do it: it writes
`pause` / `unpause` to $CTL_DIR/request and waits until the host writes the same word to $CTL_DIR/done (a host-side loop
runs `docker <word> vault-breaker-redis`).
"""
from __future__ import annotations

import asyncio
import os
import sys
import time
from pathlib import Path

from app.config.settings import Settings
from app.crypto import KeyRing
from app.errors import VaultUnavailable
from app.factory import build_vault
from app.vault import SessionRef

CTL = Path(os.environ.get("CTL_DIR", "/ctl"))
FAILED: list[str] = []


def check(name: str, ok: bool, detail: str) -> None:
    print(f"{'PASS' if ok else 'FAIL'} {name}\n     {detail}", flush=True)
    if not ok:
        FAILED.append(name)


def ask_host(action: str) -> None:
    (CTL / "request").write_text(action)
    for _ in range(300):
        if (CTL / "done").exists() and (CTL / "done").read_text() == action:
            return
        time.sleep(0.1)
    raise SystemExit(f"host did not {action} the Redis container")


async def attempt(vault, ref) -> tuple[str, float]:  # type: ignore[no-untyped-def]
    t = time.perf_counter()
    try:
        await vault.tokenize(ref, "EMAIL", f"probe-{time.time_ns()}@example.com")
        return "ok", (time.perf_counter() - t) * 1000
    except VaultUnavailable as e:
        return f"unavailable ({e})", (time.perf_counter() - t) * 1000


async def main() -> int:
    s = Settings(backend="redis", redis_url=os.environ["REDIS_URL"], ttl_seconds=3, op_timeout_s=0.25, retries=1,
                 breaker_threshold=5, breaker_cooldown_s=2.0)
    vault, client = build_vault(s, KeyRing({"k1": os.urandom(32)}, "k1"))
    ref = SessionRef("org-breaker", "session-1")
    info = await client.info("server")
    print(f"real Redis {info['redis_version']} at {os.environ['REDIS_URL']}; op timeout {s.op_timeout_s}s, retries {s.retries}, "
          f"breaker threshold {s.breaker_threshold}, cooldown {s.breaker_cooldown_s}s\n", flush=True)

    # 1. TTL on the real server
    tok = await vault.tokenize(ref, "EMAIL", "jane.doe@example.com")
    keys = [k async for k in client.scan_iter(match="*")]
    ttls = [await client.pttl(k) for k in keys]
    # EXPIREAT is set to int(deadline) + 1 (whole seconds, rounded UP so Redis never evicts early); the exact deadline is
    # enforced by the vault itself (it refuses to resolve past it even before Redis evicts). So PTTL <= (ttl + 1) s.
    check("TTL is set on every key the session wrote", bool(keys) and all(0 < t <= 4000 for t in ttls),
          f"token {tok}; {len(keys)} Redis keys, PTTL(ms)={ttls}")
    await asyncio.sleep(3.5)
    left = [k async for k in client.scan_iter(match="*")]
    got = await vault.resolve(ref, [tok])
    check("after the TTL the real server has evicted the session and the token no longer resolves", not left and got == {},
          f"keys left: {len(left)}; resolve -> {got}")

    # 2. Circuit breaker against a frozen real server
    status, ms = await attempt(vault, ref)
    check("healthy Redis: tokenize works", status == "ok", f"{status} in {ms:.1f} ms")
    ask_host("pause")
    results = [await attempt(vault, ref) for _ in range(8)]
    for i, (st, ms) in enumerate(results, 1):
        print(f"     frozen Redis, call {i}: {st} in {ms:.1f} ms", flush=True)
    slow = [ms for st, ms in results[:5]]
    fast = [ms for st, ms in results[5:]]
    check("every call fails closed while Redis is frozen (never a silent success)", all(st.startswith("unavailable") for st, _ in results), "")
    check("the first failures wait for the timeout (bounded, no hang)", all(200 <= m <= 2000 for m in slow), f"{[round(m) for m in slow]} ms")
    check("after 5 consecutive failures the breaker OPENS: calls fail in microseconds", all(m < 20 for m in fast) and
          all("circuit open" in st for st, _ in results[5:]), f"{[round(m, 2) for m in fast]} ms")
    ask_host("unpause")
    status, ms = await attempt(vault, ref)
    check("right after Redis returns, the breaker is still open (cooldown)", status.startswith("unavailable") and ms < 20, f"{status} in {ms:.2f} ms")
    await asyncio.sleep(s.breaker_cooldown_s + 0.3)
    status, ms = await attempt(vault, ref)
    check("after the cooldown the breaker lets a trial call through and the vault recovers", status == "ok", f"{status} in {ms:.1f} ms")
    await client.aclose()
    print(f"\nVAULT BREAKER (REAL REDIS): {'ALL PASSED' if not FAILED else 'FAILED: ' + ', '.join(FAILED)}", flush=True)
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
