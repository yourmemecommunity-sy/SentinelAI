from __future__ import annotations

from fastapi import APIRouter, Request, Response

from app.config.settings import DETECTOR_BUNDLE_VERSION

router = APIRouter(tags=["health"])


@router.get("/health")
def health() -> dict[str, str]:
    """Liveness: the process is up."""
    return {"status": "alive", "service": "security-engine", "detector_version": DETECTOR_BUNDLE_VERSION}


@router.get("/ready")
def ready(request: Request, response: Response) -> dict[str, object]:
    """Readiness: detectors are loaded and a canary scan blocks a known-bad input. Not ready -> callers fail closed."""
    pipeline = request.app.state.pipeline
    ok = pipeline.is_ready() and pipeline.self_test()
    if not ok:
        response.status_code = 503
    return {"status": "ready" if ok else "not_ready", "detectors": len(pipeline.registry)}
