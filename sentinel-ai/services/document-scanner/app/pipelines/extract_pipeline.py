"""Extraction pipeline: size -> type sniff -> extension check -> malware scan -> parse/OCR -> verdict.

FAIL CLOSED: every problem (too big, unknown type, mismatch, malware, scanner error, parser error, timeout, crash, OCR
unavailable, unexpected exception) yields verdict BLOCK with empty text. Nothing is persisted: bytes live only in memory.
"""
from __future__ import annotations

import hashlib

from app.config.settings import Settings
from app.extraction.isolated import run_isolated
from app.file_validation.images import image_dimensions
from app.file_validation.sniff import IMAGE_TYPES, sniff
from app.malware.scanners import EICAR, MalwareScanner
from app.models import Blocked, ExtractResult, FileInfo, Finding
from app.ocr.engine import OcrEngine
from app.parsers import Limits, extract
from app.parsers.budget import Budget
from app.utils.logging import get_logger, log_event

_log = get_logger()


class ExtractPipeline:
    def __init__(self, settings: Settings, malware: MalwareScanner, ocr: OcrEngine) -> None:
        self.settings = settings
        self.malware = malware
        self.ocr = ocr

    def run(self, data: bytes, filename: str | None = None) -> ExtractResult:
        info = FileInfo(sha256=hashlib.sha256(data).hexdigest(), size=len(data))
        findings: list[Finding] = []
        try:
            result = self._run(data, filename, info, findings)
        except Blocked as b:
            result = ExtractResult(file=info, verdict="BLOCK", block_reason=b.reason, findings=[*findings, *b.findings])
        except Exception as exc:  # noqa: BLE001 - unknown failure must block
            result = ExtractResult(file=info, verdict="BLOCK", block_reason=f"internal_error:{type(exc).__name__}",
                                   findings=[*findings, Finding(type="internal_error", severity="HIGH", detail="unexpected failure")])
        # Never log names or content: type, verdict, sizes and finding types only.
        log_event(_log, "extract_completed", sha256=info.sha256[:12], size=info.size, detected=info.detected_type,
                  verdict=result.verdict, reason=result.block_reason, findings=sorted({f.type for f in result.findings}))
        return result

    def _run(self, data: bytes, filename: str | None, info: FileInfo, findings: list[Finding]) -> ExtractResult:
        s = self.settings
        if len(data) > s.max_file_bytes:
            raise Blocked("file_too_large", [Finding(type="file_too_large", severity="MEDIUM", detail=f"exceeds {s.max_file_bytes} bytes")])

        detected = sniff(data, filename)
        info.detected_type, info.mime = detected.kind, detected.mime

        verdict = self.malware.scan(data)
        if verdict.status == "infected":
            raise Blocked("malware_detected", [Finding(type="malware_detected", severity="CRITICAL", detail=f"signature {verdict.signature}")])
        if verdict.status == "error":
            if s.malware_scan_required:
                raise Blocked("malware_scan_failed", [Finding(type="malware_scan_failed", severity="HIGH", detail="malware scan could not complete")])
            findings.append(Finding(type="malware_scan_skipped", severity="MEDIUM", detail="scanner unavailable and not required"))
        if self.malware.name == "eicar-baseline":
            findings.append(Finding(type="malware_scan_baseline_only", severity="INFO", detail="only the EICAR test signature is checked; not real antivirus"))

        ocr_used = False
        pages: int | None = None
        if detected.kind in IMAGE_TYPES:
            w, h = image_dimensions(detected.kind, data)
            if w * h > s.max_image_pixels:
                raise Blocked("image_too_large", [Finding(type="image_too_large", severity="MEDIUM", detail=f"{w}x{h} exceeds pixel limit")])
            text = self.ocr.extract(data, detected.mime)          # raises Blocked(ocr_unavailable) when no engine is configured
            Budget(s.max_text_chars).add(text)
            ocr_used = True
            if not text.strip():
                findings.append(Finding(type="ocr_no_text", severity="INFO", detail="no text recognised; image content beyond text was NOT inspected"))
        else:
            limits = Limits(s.max_text_chars, s.max_pdf_pages)
            if s.isolation:
                text, more, pages = run_isolated(detected.kind, data, limits, s.extract_timeout_s)
            else:
                text, more, pages = extract(detected.kind, data, limits)
            findings.extend(more)

        return ExtractResult(file=info, verdict="OK", text=text, text_chars=len(text), pages=pages, ocr_used=ocr_used, findings=findings)

    def self_test(self) -> bool:
        """Canaries for /ready: the malware scanner must flag EICAR, and a trivial file must extract."""
        try:
            if self.malware.scan(EICAR).status != "infected":
                return False
            r = self.run(b"hello", "canary.txt")
            return r.verdict == "OK" and r.text == "hello"
        except Exception:  # noqa: BLE001
            return False
