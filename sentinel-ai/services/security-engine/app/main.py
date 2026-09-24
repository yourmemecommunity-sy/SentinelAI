"""Security engine FastAPI app. Run: uvicorn app.main:app --port 8001"""
from __future__ import annotations

from fastapi import FastAPI

from app.api.routes import health, scan
from app.config.settings import Settings
from app.pipelines import ScanPipeline, default_pipeline


def create_app(settings: Settings | None = None, pipeline: ScanPipeline | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    app = FastAPI(title="SentinelAI Security Engine", version="0.1.0")
    app.state.settings = settings
    app.state.pipeline = pipeline or default_pipeline(settings)
    app.include_router(health.router)
    app.include_router(scan.router)
    return app


app = create_app()
