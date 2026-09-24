from __future__ import annotations

import json
import logging
import sys
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI

from app.api import add_health, router
from app.config.settings import Settings
from app.crypto import KeyRing
from app.factory import build_vault


class _JsonFormatter(logging.Formatter):
    """One JSON object per line. Only the fields passed via `extra={"fields": ...}` are emitted: never values, tokens or keys."""

    def format(self, record: logging.LogRecord) -> str:
        return json.dumps({"level": record.levelname, "logger": record.name, "msg": record.getMessage(), **getattr(record, "fields", {})})


def _configure_logging() -> None:
    log = logging.getLogger("sentinel.token_vault")
    if not log.handlers:
        h = logging.StreamHandler(sys.stdout)
        h.setFormatter(_JsonFormatter())
        log.addHandler(h)
        log.setLevel(logging.INFO)
        log.propagate = False


def create_app(settings: Settings | None = None, keyring: KeyRing | None = None) -> FastAPI:
    _configure_logging()
    if settings is None:
        settings, keyring = Settings.from_env()
    if keyring is None:
        # Not an assert: `python -O` strips those, and a missing key ring must fail loudly rather than surface later as an
        # AttributeError deep inside a tokenize call.
        raise RuntimeError("a KeyRing must be supplied when settings are passed explicitly")
    vault, client = build_vault(settings, keyring)

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        yield
        await client.aclose()

    app = FastAPI(title="SentinelAI Token Vault", version="0.1.0", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.state.settings = settings
    app.state.vault = vault
    app.include_router(router)
    add_health(app)
    if settings.ephemeral_keys:
        logging.getLogger("sentinel.token_vault").warning("no VAULT_MASTER_KEYS configured: using an ephemeral key (development only)")
    return app


app = create_app()
