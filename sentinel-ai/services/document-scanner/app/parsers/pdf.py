"""PDF extraction with active-content detection (JavaScript, Launch actions, embedded files, rich media, encryption).

Active content is looked for in two independent ways so neither raw-byte tricks (`/J#53`) nor object-stream compression
(names hidden from a byte search) can hide it: a normalized raw-byte scan and a walk over every parsed object.
Known limit: text that is visually hidden (white/tiny/clipped) inside page content streams is extracted like any other
text, but is not *identified* as hidden (that needs rendering).
"""
from __future__ import annotations

import io
import re
from collections.abc import Mapping
from typing import Any

from pypdf import PdfReader
from pypdf.generic import ArrayObject, DictionaryObject, IndirectObject

from app.models import Blocked, Finding, Severity
from app.parsers.budget import Budget

_HEX_ESCAPE = re.compile(rb"#([0-9A-Fa-f]{2})")
_RAW_ACTIVE = re.compile(rb"/(JavaScript|JS|Launch|RichMedia|EmbeddedFile|EmbeddedFiles|SubmitForm|ImportData|GoToE|Rendition|XFA)\b")
_ACTION_TYPES = {"/JavaScript", "/Launch", "/SubmitForm", "/ImportData", "/GoToE", "/Rendition"}
_ACTIVE_KEYS = {"/JS", "/JavaScript"}
MAX_OBJECTS = 100_000


def _block(reason: str, detail: str, severity: Severity = "CRITICAL") -> Blocked:
    return Blocked(reason, [Finding(type=reason, severity=severity, detail=detail)])


def _normalize_names(data: bytes) -> bytes:
    return _HEX_ESCAPE.sub(lambda m: bytes([int(m.group(1), 16)]), data)


def _inspect(obj: object, depth: int = 0) -> str | None:
    """Look for active-content markers in a dictionary and in every dictionary/array nested inside it (bounded depth).
    Indirect references are not followed here: the caller visits every object in the file anyway."""
    if depth > 12:
        return None
    if isinstance(obj, DictionaryObject):
        if obj.get("/S") in _ACTION_TYPES:
            return f"action {obj.get('/S')}"
        if any(k in obj for k in _ACTIVE_KEYS):
            return "JavaScript"
        if obj.get("/Type") == "/EmbeddedFile" or "/EmbeddedFiles" in obj:
            return "embedded file"
        if obj.get("/Subtype") in ("/RichMedia", "/Screen") or "/RichMedia" in obj:
            return "rich media"
        for v in obj.values():
            if isinstance(v, (DictionaryObject, ArrayObject)):
                hit = _inspect(v, depth + 1)
                if hit:
                    return hit
    elif isinstance(obj, ArrayObject):
        for v in obj:
            if isinstance(v, (DictionaryObject, ArrayObject)):
                hit = _inspect(v, depth + 1)
                if hit:
                    return hit
    return None


def _active_in_objects(reader: PdfReader) -> str | None:
    """Walk every object (including those compressed in object streams) looking for active content."""
    numbers: list[int] = []
    try:
        numbers = [n for gens in reader.xref.values() for n in gens]
        numbers += list(getattr(reader, "xref_objStm", {}).keys())
    except Exception:  # noqa: BLE001
        pass
    for num in numbers[:MAX_OBJECTS]:
        try:
            obj = reader.get_object(IndirectObject(num, 0, reader))
        except Exception:  # noqa: BLE001
            continue
        hit = _inspect(obj)
        if hit:
            return hit
    return None


def extract_pdf(data: bytes, budget: Budget, max_pages: int = 500) -> tuple[str, list[Finding], int]:
    findings: list[Finding] = []
    raw_hit = _RAW_ACTIVE.search(_normalize_names(data))
    if raw_hit:
        raise _block("pdf_active_content", f"PDF contains {raw_hit.group(1).decode()} (active or embedded content)")

    try:
        reader = PdfReader(io.BytesIO(data), strict=False)
        if reader.is_encrypted:
            raise _block("encrypted_document", "encrypted PDF cannot be inspected", "HIGH")
        pages = len(reader.pages)
    except Blocked:
        raise
    except Exception:  # noqa: BLE001 - malformed input of any kind is not inspectable
        raise _block("parse_error", "PDF could not be parsed", "MEDIUM") from None
    if pages > max_pages:
        raise _block("page_limit", f"{pages} pages exceeds limit {max_pages}", "MEDIUM")

    hit = _active_in_objects(reader)
    if hit:
        raise _block("pdf_active_content", f"PDF contains {hit}")

    out: list[str] = []
    try:
        for page in reader.pages:
            text = page.extract_text() or ""
            if text.strip():
                out.append(budget.add(text))
            annots = page.get("/Annots")
            if annots:
                for a in (annots if isinstance(annots, ArrayObject) else []):
                    ao = a.get_object() if hasattr(a, "get_object") else a
                    contents = ao.get("/Contents") if isinstance(ao, DictionaryObject) else None
                    if contents:
                        out.append(budget.add(f"[annotation] {contents}"))
        meta: Mapping[str, Any] = reader.metadata or {}
        for key in ("/Title", "/Author", "/Subject", "/Keywords", "/Creator", "/Producer"):
            val = meta.get(key)
            if val and str(val).strip():
                out.append(budget.add(f"[metadata:{key[1:].lower()}] {val}"))
        fields = reader.get_fields() or {}
        for name, f in fields.items():
            v = f.get("/V") if isinstance(f, dict) else None
            if v is not None and str(v).strip():
                out.append(budget.add(f"[field:{name}] {v}"))
    except Blocked:
        raise
    except Exception:  # noqa: BLE001
        raise _block("parse_error", "PDF text extraction failed", "MEDIUM") from None

    if not any(o.strip() for o in out):
        findings.append(Finding(type="no_extractable_text", severity="MEDIUM",
                                detail="PDF has no extractable text (scanned images?); its visual content was NOT inspected"))
    return "\n".join(out), findings, pages
