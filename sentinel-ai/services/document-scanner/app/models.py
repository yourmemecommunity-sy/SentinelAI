"""Wire models and the internal Blocked exception.

Design rule: any inability to inspect a file safely raises `Blocked(reason)`. The pipeline converts it into verdict BLOCK.
Nothing is ever "allowed by default" because parsing failed.
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

Severity = Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


class Finding(BaseModel):
    type: str
    severity: Severity
    detail: str


class FileInfo(BaseModel):
    sha256: str
    size: int
    detected_type: str | None = None
    mime: str | None = None


class ExtractResult(BaseModel):
    file: FileInfo
    verdict: Literal["OK", "BLOCK"]
    block_reason: str | None = None
    #: Extracted text. ALWAYS empty when verdict is BLOCK.
    text: str = ""
    text_chars: int = 0
    pages: int | None = None
    ocr_used: bool = False
    findings: list[Finding] = Field(default_factory=list)


class Blocked(Exception):
    def __init__(self, reason: str, findings: list[Finding] | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.findings = findings or []
