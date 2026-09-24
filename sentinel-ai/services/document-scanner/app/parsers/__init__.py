"""Parser dispatch. `extract` is what runs inside the isolated child process."""
from __future__ import annotations

from dataclasses import dataclass

from app.models import Blocked, Finding
from app.parsers.budget import Budget
from app.parsers.ooxml import extract_docx, extract_xlsx
from app.parsers.pdf import extract_pdf
from app.parsers.text import extract_csv, extract_json, extract_txt


@dataclass(frozen=True)
class Limits:
    max_text_chars: int
    max_pdf_pages: int


def extract(kind: str, data: bytes, limits: Limits) -> tuple[str, list[Finding], int | None]:
    budget = Budget(limits.max_text_chars)
    if kind == "pdf":
        return extract_pdf(data, budget, limits.max_pdf_pages)
    if kind == "docx":
        text, findings = extract_docx(data, budget)
    elif kind == "xlsx":
        text, findings = extract_xlsx(data, budget)
    elif kind == "csv":
        text, findings = extract_csv(data, budget)
    elif kind == "json":
        text, findings = extract_json(data, budget)
    elif kind == "txt":
        text, findings = extract_txt(data, budget)
    else:
        raise Blocked("unsupported_type", [Finding(type="unsupported_type", severity="HIGH", detail=f"no parser for {kind}")])
    return text, findings, None
