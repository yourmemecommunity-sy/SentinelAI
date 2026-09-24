"""Document scanner FastAPI app. Run: uvicorn app.main:app --port 8003"""
from __future__ import annotations

from fastapi import FastAPI

from app.api.routes import health_router, router
from app.config.settings import Settings
from app.malware.scanners import build_scanner
from app.ocr.engine import build_ocr
from app.pipelines.extract_pipeline import ExtractPipeline


def create_app(settings: Settings | None = None, pipeline: ExtractPipeline | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    app = FastAPI(title="SentinelAI Document Scanner", version="0.1.0")
    app.state.settings = settings
    app.state.pipeline = pipeline or ExtractPipeline(
        settings, build_scanner(settings.malware_scanner, settings.clamd_host, settings.clamd_port), build_ocr(settings.tesseract_cmd))
    app.include_router(health_router)
    app.include_router(router)
    return app


app = create_app()
