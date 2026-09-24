from __future__ import annotations

import hmac
from urllib.parse import unquote

from fastapi import APIRouter, Depends, HTTPException, Request, Response

from app.models import ExtractResult
from app.pipelines.extract_pipeline import ExtractPipeline

router = APIRouter(tags=["extract"])


def get_pipeline(request: Request) -> ExtractPipeline:
    pipeline: ExtractPipeline = request.app.state.pipeline    # set once at startup (app.main)
    return pipeline


def require_internal_token(request: Request) -> None:
    expected: str | None = request.app.state.settings.internal_token
    if expected is None:
        return  # development only; Settings.from_env refuses to start in production without a token
    given = request.headers.get("x-internal-token")
    if given is None or not hmac.compare_digest(given, expected):
        raise HTTPException(status_code=401, detail="invalid internal token")


async def _read_capped(request: Request, limit: int) -> bytes:
    """Read the body while enforcing the size cap, so an oversized upload is rejected without being buffered."""
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > limit:
        raise HTTPException(status_code=413, detail="file too large")
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > limit:
            raise HTTPException(status_code=413, detail="file too large")
        chunks.append(chunk)
    return b"".join(chunks)


@router.post("/v1/extract", response_model=ExtractResult, dependencies=[Depends(require_internal_token)])
async def extract(request: Request, pipeline: ExtractPipeline = Depends(get_pipeline)) -> ExtractResult:
    """Raw file bytes in the body; optional `X-Filename` (percent-encoded) used ONLY for the extension/content consistency check."""
    data = await _read_capped(request, pipeline.settings.max_file_bytes)
    raw_name = request.headers.get("x-filename")
    filename = unquote(raw_name)[:255] if raw_name else None
    # Extraction is CPU-bound and may spawn a child process: keep it off the event loop.
    from starlette.concurrency import run_in_threadpool
    return await run_in_threadpool(pipeline.run, data, filename)


health_router = APIRouter(tags=["health"])


@health_router.get("/health")
def health() -> dict[str, str]:
    return {"status": "alive", "service": "document-scanner"}


@health_router.get("/ready")
def ready(request: Request, response: Response) -> dict[str, object]:
    """Ready only if the malware scanner works (canary: it must flag EICAR) and a trivial extraction succeeds."""
    p: ExtractPipeline = request.app.state.pipeline
    ok = p.self_test() and (p.malware.healthy() or not p.settings.malware_scan_required)
    if not ok:
        response.status_code = 503
    return {"status": "ready" if ok else "not_ready", "malware_scanner": p.malware.name, "ocr": p.ocr.name}
