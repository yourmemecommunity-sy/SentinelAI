"""HTTP surface (internal only). Every route needs X-Internal-Token; responses are `no-store`; nothing here logs values.

POST /v1/vault/tokenize    {organization_id, session_id, items:[{entity,value}], refuse?}  -> {tokens:[...]}  (refuse:"null" -> null for refused types)
POST /v1/vault/resolve     {organization_id, session_id, tokens:[...]}                -> {values:{token:value}}
POST /v1/vault/detokenize  {organization_id, session_id, payload:{...}}               -> {payload:{...}}
DELETE /v1/vault/sessions  {organization_id, session_id}                              -> 204
GET /health, /ready
"""
from __future__ import annotations

import hmac
import json
import logging
from typing import Any, Literal

from fastapi import APIRouter, FastAPI, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.detokenize import detokenize_json
from app.errors import TokenizationRefused, VaultLimitExceeded, VaultUnavailable
from app.vault import SessionRef

_log = logging.getLogger("sentinel.token_vault")
_ID = r"^[A-Za-z0-9_.:@-]{1,128}$"


class _Base(BaseModel):
    model_config = ConfigDict(extra="forbid")
    organization_id: str = Field(pattern=_ID)
    session_id: str = Field(pattern=_ID)


class Item(BaseModel):
    model_config = ConfigDict(extra="forbid")
    entity: str = Field(pattern=r"^[A-Z](?:[A-Z_]{0,30}[A-Z])?$")
    value: str = Field(min_length=1)


class TokenizeBody(_Base):
    items: list[Item] = Field(min_length=1)
    # "error": one non-tokenizable entity type rejects the whole request (422). "null": those items get a null token instead.
    refuse: Literal["error", "null"] = "error"


class ResolveBody(_Base):
    tokens: list[str] = Field(min_length=1, max_length=4096)


class DetokenizeBody(_Base):
    payload: dict[str, Any]


class SessionBody(_Base):
    pass


router = APIRouter(prefix="/v1/vault")


def _authorize(request: Request) -> None:
    expected: str | None = request.app.state.settings.internal_token
    if expected is None:
        return  # development only; Settings.from_env refuses to start in production without a token
    got = request.headers.get("x-internal-token")
    if got is None or not hmac.compare_digest(got, expected):
        raise HTTPException(status_code=401, detail="invalid internal token")


async def _read(request: Request, model: type[BaseModel]) -> Any:
    """Auth first, then a size-capped read (a client that lies about Content-Length still cannot make us buffer more)."""
    _authorize(request)
    limit: int = request.app.state.settings.max_body_bytes
    if int(request.headers.get("content-length") or 0) > limit:
        raise HTTPException(status_code=413, detail="body too large")
    buf = bytearray()
    async for part in request.stream():
        buf += part
        if len(buf) > limit:
            raise HTTPException(status_code=413, detail="body too large")
    try:
        return model.model_validate(json.loads(bytes(buf) or b"null"))
    except (ValidationError, ValueError, UnicodeDecodeError):
        raise HTTPException(status_code=422, detail="invalid request") from None  # never echo the offending input


def _ref(b: _Base) -> SessionRef:
    return SessionRef(b.organization_id, b.session_id)


def _json(body: Any, status: int = 200) -> Response:
    return Response(json.dumps(body), status_code=status, media_type="application/json", headers={"cache-control": "no-store"})


@router.post("/tokenize")
async def tokenize(request: Request) -> Response:
    b: TokenizeBody = await _read(request, TokenizeBody)
    vault = request.app.state.vault
    try:
        pairs = [(i.entity, i.value) for i in b.items]
        tokens = await (vault.tokenize_partial if b.refuse == "null" else vault.tokenize_many)(_ref(b), pairs)
    except TokenizationRefused:
        raise HTTPException(status_code=422, detail="entity_not_tokenizable") from None
    except VaultLimitExceeded:
        raise HTTPException(status_code=413, detail="vault_limit_exceeded") from None
    except VaultUnavailable:
        raise HTTPException(status_code=503, detail="vault_unavailable") from None
    _log.info("tokenized", extra={"fields": {"organization_id": b.organization_id, "count": len(tokens)}})
    return _json({"tokens": tokens})


@router.post("/resolve")
async def resolve(request: Request) -> Response:
    b: ResolveBody = await _read(request, ResolveBody)
    try:
        values = await request.app.state.vault.resolve(_ref(b), b.tokens)
    except VaultUnavailable:
        raise HTTPException(status_code=503, detail="vault_unavailable") from None
    _log.info("resolved", extra={"fields": {"organization_id": b.organization_id, "requested": len(b.tokens), "resolved": len(values)}})
    return _json({"values": values})


@router.post("/detokenize")
async def detokenize(request: Request) -> Response:
    b: DetokenizeBody = await _read(request, DetokenizeBody)
    try:
        out = await detokenize_json(b.payload, b.session_id, vault=request.app.state.vault, org_id=b.organization_id)
    except VaultUnavailable:
        raise HTTPException(status_code=503, detail="vault_unavailable") from None
    except ValueError:
        raise HTTPException(status_code=422, detail="payload_too_large_or_deep") from None
    return _json({"payload": out})


@router.delete("/sessions")
async def delete_session(request: Request) -> Response:
    b: SessionBody = await _read(request, SessionBody)
    try:
        await request.app.state.vault.delete_session(_ref(b))
    except VaultUnavailable:
        raise HTTPException(status_code=503, detail="vault_unavailable") from None
    return Response(status_code=204, headers={"cache-control": "no-store"})


def add_health(app: FastAPI) -> None:
    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/ready")
    async def ready(response: Response) -> dict[str, object]:
        ok = await app.state.vault.ready()
        if not ok:
            response.status_code = 503
        return {"status": "ready" if ok else "not_ready"}
