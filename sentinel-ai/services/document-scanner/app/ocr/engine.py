"""OCR interface. Images are only accepted if their text can be inspected; otherwise they are blocked (fail closed).

TesseractOcr feeds the image to the `tesseract` binary over stdin and reads text from stdout: nothing is written to disk.
"""
from __future__ import annotations

import shutil
import subprocess
from typing import Protocol

from app.models import Blocked, Finding


class OcrEngine(Protocol):
    name: str

    def available(self) -> bool: ...
    def extract(self, data: bytes, mime: str) -> str: ...


class UnavailableOcr:
    name = "none"

    def available(self) -> bool:
        return False

    def extract(self, data: bytes, mime: str) -> str:
        raise Blocked("ocr_unavailable", [Finding(type="ocr_unavailable", severity="HIGH",
                                                 detail="no OCR engine configured; image text cannot be inspected")])


class TesseractOcr:
    name = "tesseract"

    def __init__(self, cmd: str | None = None, timeout: float = 60.0, lang: str = "eng") -> None:
        self.cmd = cmd or shutil.which("tesseract")
        self.timeout = timeout
        self.lang = lang

    def available(self) -> bool:
        return bool(self.cmd)

    def extract(self, data: bytes, mime: str) -> str:
        if not self.cmd:
            raise Blocked("ocr_unavailable", [Finding(type="ocr_unavailable", severity="HIGH", detail="tesseract not found")])
        try:
            p = subprocess.run([self.cmd, "stdin", "stdout", "-l", self.lang], input=data, capture_output=True, timeout=self.timeout, check=False)
        except (OSError, subprocess.TimeoutExpired):
            raise Blocked("ocr_failed", [Finding(type="ocr_failed", severity="HIGH", detail="OCR did not complete")]) from None
        if p.returncode != 0:
            raise Blocked("ocr_failed", [Finding(type="ocr_failed", severity="HIGH", detail="OCR engine reported an error")])
        return p.stdout.decode("utf-8", "replace")


def build_ocr(tesseract_cmd: str | None) -> OcrEngine:
    engine = TesseractOcr(tesseract_cmd)
    return engine if engine.available() else UnavailableOcr()
