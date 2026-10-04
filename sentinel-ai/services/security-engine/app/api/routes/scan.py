from __future__ import annotations

import hmac

from fastapi import APIRouter, Depends, Header, HTTPException, Request

from app.api.schemas.scan import ScanRequest, ScanResult
from app.pipelines import ScanPipeline
from app.replay import ReplayRequest, ReplayResult, replay

router = APIRouter(prefix="/v1", tags=["scan"])


def get_pipeline(request: Request) -> ScanPipeline:
    pipeline: ScanPipeline = request.app.state.pipeline    # set once at startup (app.main)
    return pipeline


def require_internal_token(request: Request, x_internal_token: str | None = Header(default=None)) -> None:
    expected: str | None = request.app.state.settings.internal_token
    if expected is None:
        return  # development only; Settings.from_env refuses to start in production without a token
    if x_internal_token is None or not hmac.compare_digest(x_internal_token, expected):
        raise HTTPException(status_code=401, detail="invalid internal token")


@router.post("/scan", response_model=ScanResult, dependencies=[Depends(require_internal_token)])
def scan(body: ScanRequest, pipeline: ScanPipeline = Depends(get_pipeline)) -> ScanResult:
    return pipeline.scan(body)


@router.post("/replay", response_model=ReplayResult, dependencies=[Depends(require_internal_token)])
def replay_decision(body: ReplayRequest, pipeline: ScanPipeline = Depends(get_pipeline)) -> ReplayResult:
    """Re-run a recorded decision with the original input (see app.replay). Read-only: no vault, no event."""
    return replay(pipeline, body)
