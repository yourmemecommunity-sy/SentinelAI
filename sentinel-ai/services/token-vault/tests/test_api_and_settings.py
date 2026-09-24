import base64
import dataclasses

import httpx
import pytest

from app.config.settings import Settings
from app.crypto import KeyRing
from app.main import create_app
from tests.conftest import KEY1

TOKEN = "vault-internal-token-1234"
SECRET_VALUE = "sk-live-not-a-real-credential-0000"


@pytest.fixture
async def client(settings):
    app = create_app(dataclasses.replace(settings, internal_token=TOKEN, max_body_bytes=4096), KeyRing({"k1": KEY1}, "k1"))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://vault.test", headers={"x-internal-token": TOKEN}) as c:
        yield c


def body(**over):
    return {"organization_id": "org-1", "session_id": "sess-1", **over}


async def test_tokenize_resolve_detokenize_roundtrip(client):
    r = await client.post("/v1/vault/tokenize", json=body(items=[{"entity": "NAME", "value": "John Doe"}, {"entity": "EMAIL", "value": "j@example.com"}]))
    assert r.status_code == 200 and r.json() == {"tokens": ["[TOK_NAME_1]", "[TOK_EMAIL_1]"]}
    assert r.headers["cache-control"] == "no-store"

    r = await client.post("/v1/vault/resolve", json=body(tokens=["[TOK_NAME_1]", "[TOK_NAME_7]"]))
    assert r.json() == {"values": {"[TOK_NAME_1]": "John Doe"}}

    r = await client.post("/v1/vault/detokenize", json=body(payload={"msg": "hi [TOK_NAME_1]", "n": [1, "[TOK_EMAIL_1]"]}))
    assert r.json() == {"payload": {"msg": "hi John Doe", "n": [1, "j@example.com"]}}


async def test_tenants_and_sessions_are_isolated_through_the_api(client):
    await client.post("/v1/vault/tokenize", json=body(items=[{"entity": "NAME", "value": "John Doe"}]))
    for other in (body(organization_id="org-2"), body(session_id="sess-2")):
        r = await client.post("/v1/vault/resolve", json={**other, "tokens": ["[TOK_NAME_1]"]})
        assert r.status_code == 200 and r.json() == {"values": {}}


async def test_delete_session(client):
    await client.post("/v1/vault/tokenize", json=body(items=[{"entity": "NAME", "value": "John Doe"}]))
    r = await client.request("DELETE", "/v1/vault/sessions", json=body())
    assert r.status_code == 204
    assert (await client.post("/v1/vault/resolve", json=body(tokens=["[TOK_NAME_1]"]))).json() == {"values": {}}


@pytest.mark.parametrize("path,payload", [
    ("/v1/vault/tokenize", body(items=[{"entity": "NAME", "value": "x"}])),
    ("/v1/vault/resolve", body(tokens=["[TOK_NAME_1]"])),
    ("/v1/vault/detokenize", body(payload={})),
])
async def test_every_route_requires_the_internal_token(client, path, payload):
    for headers in ({}, {"x-internal-token": "wrong"}, {"x-internal-token": TOKEN[:-1]}):
        r = await client.post(path, json=payload, headers={"x-internal-token": "", **headers} if not headers else headers)
        assert r.status_code == 401, (path, headers)
    r = await client.request("DELETE", "/v1/vault/sessions", json=body(), headers={"x-internal-token": "wrong"})
    assert r.status_code == 401


async def test_credentials_are_refused_422_without_echoing_the_value(client):
    for entity in ["PASSWORD", "API_KEY", "PRIVATE_KEY", "CREDIT_CARD"]:
        r = await client.post("/v1/vault/tokenize", json=body(items=[{"entity": entity, "value": SECRET_VALUE}]))
        assert r.status_code == 422 and r.json() == {"detail": "entity_not_tokenizable"}
        assert SECRET_VALUE not in r.text


async def test_invalid_requests_are_422_and_never_echo_input(client):
    cases = [
        body(items=[]), body(items=[{"entity": "name", "value": SECRET_VALUE}]), body(items=[{"entity": "NAME", "value": ""}]),
        {**body(items=[{"entity": "NAME", "value": SECRET_VALUE}]), "extra": 1}, {"session_id": "s", "items": [{"entity": "NAME", "value": SECRET_VALUE}]},
        body(session_id="bad id " + SECRET_VALUE, items=[{"entity": "NAME", "value": "x"}]), body(session_id="s\n", items=[{"entity": "NAME", "value": "x"}]),
    ]
    for c in cases:
        r = await client.post("/v1/vault/tokenize", json=c)
        assert r.status_code == 422, c
        assert SECRET_VALUE not in r.text
    r = await client.post("/v1/vault/tokenize", content=b"{not json " + SECRET_VALUE.encode())
    assert r.status_code == 422 and SECRET_VALUE not in r.text
    assert (await client.post("/v1/vault/resolve", json=body(tokens=[]))).status_code == 422


async def test_oversized_bodies_are_rejected_before_parsing(client):
    big = body(items=[{"entity": "NAME", "value": "x" * 6000}])
    assert (await client.post("/v1/vault/tokenize", json=big)).status_code == 413
    async def gen():                                            # no Content-Length: chunked
        for _ in range(10):
            yield b"x" * 1000
    assert (await client.post("/v1/vault/tokenize", content=gen())).status_code == 413


async def test_limits_map_to_413(client, settings):
    app = create_app(dataclasses.replace(settings, internal_token=TOKEN, max_tokens_per_session=1), KeyRing({"k1": KEY1}, "k1"))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://v", headers={"x-internal-token": TOKEN}) as c:
        assert (await c.post("/v1/vault/tokenize", json=body(items=[{"entity": "NAME", "value": "a"}]))).status_code == 200
        r = await c.post("/v1/vault/tokenize", json=body(items=[{"entity": "NAME", "value": "b"}]))
        assert r.status_code == 413 and r.json() == {"detail": "vault_limit_exceeded"}


async def test_deep_json_is_rejected(client):
    deep: dict = {}
    node = deep
    for _ in range(100):
        node["x"] = {}
        node = node["x"]
    r = await client.post("/v1/vault/detokenize", json=body(payload=deep))
    assert r.status_code == 422 and r.json() == {"detail": "payload_too_large_or_deep"}


async def test_outage_is_503_and_ready_reflects_it(settings):
    from app.crypto import KeyRing as KR
    app = create_app(dataclasses.replace(settings, internal_token=None), KR({"k1": KEY1}, "k1"))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://v") as c:
        assert (await c.get("/health")).json() == {"status": "ok"}
        assert (await c.get("/ready")).status_code == 200
        # simulate a Redis outage at the backend boundary
        async def boom(*a, **k):
            from app.errors import VaultUnavailable
            raise VaultUnavailable("x")
        app.state.vault._b._run = boom
        assert (await c.get("/ready")).status_code == 503
        for path, payload in [("/v1/vault/tokenize", body(items=[{"entity": "NAME", "value": "a"}])), ("/v1/vault/resolve", body(tokens=["[TOK_NAME_1]"])),
                              ("/v1/vault/detokenize", body(payload={"a": "[TOK_NAME_1]"}))]:
            r = await c.post(path, json=payload)
            assert r.status_code == 503 and r.json() == {"detail": "vault_unavailable"}, path


async def test_no_openapi_or_docs_are_exposed(client):
    for p in ["/docs", "/redoc", "/openapi.json"]:
        assert (await client.get(p)).status_code == 404


# ------------------------------------------------------------------ settings (fail closed on misconfiguration)
def env(monkeypatch, **kv):
    for k in ["SENTINEL_ENV", "VAULT_TOKEN", "VAULT_BACKEND", "VAULT_MASTER_KEYS", "VAULT_ACTIVE_KEY", "VAULT_TTL_SECONDS", "REDIS_URL"]:
        monkeypatch.delenv(k, raising=False)
    for k, v in kv.items():
        monkeypatch.setenv(k, v)


KEYS = "k1:" + base64.b64encode(KEY1).decode()


def test_defaults_match_the_retention_mandate(monkeypatch):
    env(monkeypatch)
    s, ring = Settings.from_env()
    assert s.ttl_seconds == 3600 and s.ephemeral_keys and s.backend == "redis"
    assert ring.active == "dev"


def test_production_refuses_unsafe_configuration(monkeypatch):
    base = {"SENTINEL_ENV": "production", "VAULT_TOKEN": "t" * 20, "VAULT_MASTER_KEYS": KEYS}
    env(monkeypatch, **base)
    Settings.from_env()                                                                       # the complete config is accepted
    for drop_or_set in [{"VAULT_TOKEN": ""}, {"VAULT_TOKEN": "short"}, {"VAULT_BACKEND": "memory"}, {"VAULT_MASTER_KEYS": ""}]:
        env(monkeypatch, **{**base, **drop_or_set})
        with pytest.raises(RuntimeError):
            Settings.from_env()


def test_ttl_bounds_and_backend_values(monkeypatch):
    for bad in ["0", "-5", "86401"]:
        env(monkeypatch, VAULT_TTL_SECONDS=bad)
        with pytest.raises(RuntimeError):
            Settings.from_env()
    env(monkeypatch, VAULT_BACKEND="mongo")
    with pytest.raises(RuntimeError):
        Settings.from_env()


def test_master_key_parsing_never_echoes_the_value(monkeypatch):
    env(monkeypatch, VAULT_MASTER_KEYS="k1:not!!base64-SECRETMARKER")
    with pytest.raises(RuntimeError) as e:
        Settings.from_env()
    assert "SECRETMARKER" not in str(e.value)
    env(monkeypatch, VAULT_MASTER_KEYS=f"k1:{base64.b64encode(b'short').decode()}")
    with pytest.raises(ValueError):
        Settings.from_env()
    two = f"k1:{base64.b64encode(KEY1).decode()},k2:{base64.b64encode(bytes(range(50, 82))).decode()}"
    env(monkeypatch, VAULT_MASTER_KEYS=two, VAULT_ACTIVE_KEY="k2")
    _, ring = Settings.from_env()
    assert ring.active == "k2" and ring.has("k1")


# ------------------------------------------------------------------ Redis client construction (real-Redis regression)
def test_redis_client_uses_a_bounded_blocking_pool(settings):
    """Found against a real Redis server: the default pool raises MaxConnectionsError above its limit, which is a
    ConnectionError subclass, so a burst of concurrent tokenization would be treated as an outage and fail every request
    closed. The pool must be bounded AND blocking so bursts queue instead."""
    import dataclasses

    import redis.asyncio as aioredis

    from app.factory import build_client

    c = build_client(dataclasses.replace(settings, backend="redis", redis_url="redis://127.0.0.1:6379/0", redis_max_connections=32))
    pool = c.connection_pool
    assert isinstance(pool, aioredis.BlockingConnectionPool)
    assert pool.max_connections == 32
    assert dataclasses.replace(settings, backend="memory").backend == "memory"
