"""Environment-driven settings. Every limit has a safe default; production refuses unsafe configurations."""
from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    environment: str = "development"
    internal_token: str | None = None
    max_file_bytes: int = 20 * 1024 * 1024
    #: Extracted text above this is BLOCKED (never silently truncated). Must stay below the security engine's input cap.
    max_text_chars: int = 450_000
    max_pdf_pages: int = 500
    max_image_pixels: int = 50_000_000
    extract_timeout_s: float = 20.0
    #: Run parsers in a separate process so a parser crash/hang/exploit cannot take down or stall the service.
    isolation: bool = True
    #: "clamd" (real AV over the clamd protocol), "eicar" (baseline: detects only the EICAR test file), "none".
    malware_scanner: str = "eicar"
    clamd_host: str = "127.0.0.1"
    clamd_port: int = 3310
    #: When true, no scanner / an unreachable scanner means files are blocked and /ready reports 503.
    malware_scan_required: bool = True
    tesseract_cmd: str | None = None

    @classmethod
    def from_env(cls) -> "Settings":
        e = os.environ.get
        env = e("SENTINEL_ENV", "development")
        s = cls(
            environment=env,
            internal_token=e("DOC_SCANNER_TOKEN") or None,
            max_file_bytes=int(e("MAX_FILE_BYTES", str(20 * 1024 * 1024))),
            max_text_chars=int(e("MAX_TEXT_CHARS", "450000")),
            max_pdf_pages=int(e("MAX_PDF_PAGES", "500")),
            extract_timeout_s=float(e("EXTRACT_TIMEOUT_S", "20")),
            isolation=e("EXTRACT_ISOLATION", "true").lower() != "false",
            malware_scanner=e("MALWARE_SCANNER", "clamd" if env == "production" else "eicar"),
            clamd_host=e("CLAMD_HOST", "127.0.0.1"),
            clamd_port=int(e("CLAMD_PORT", "3310")),
            malware_scan_required=e("MALWARE_SCAN_REQUIRED", "true").lower() != "false",
            tesseract_cmd=e("TESSERACT_CMD") or None,
        )
        if env == "production":
            # Fail closed on misconfiguration: never run an unauthenticated scanner, or a fake AV, in production.
            if not s.internal_token:
                raise RuntimeError("DOC_SCANNER_TOKEN must be set when SENTINEL_ENV=production")
            if s.malware_scan_required and s.malware_scanner != "clamd":
                raise RuntimeError("production requires MALWARE_SCANNER=clamd (or an explicit MALWARE_SCAN_REQUIRED=false)")
            if not s.isolation:
                raise RuntimeError("EXTRACT_ISOLATION must stay enabled in production")
        return s
