"""Content-based file type detection (magic bytes, never the extension) with a strict allow-list.

Allowed: pdf, docx, xlsx, csv, txt, json, png, jpeg, gif, webp. Everything else is blocked, including executables,
scripts, archives, legacy Office (macro-capable OLE) and OOXML types we do not parse (pptx).
The claimed extension must agree with the detected content; a mismatch is a classic evasion and is blocked.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass

from app.file_validation.safe_zip import ZipLimits, open_safe
from app.models import Blocked, Finding, Severity

ALLOWED_TYPES = {"pdf", "docx", "xlsx", "csv", "txt", "json", "png", "jpeg", "gif", "webp"}
IMAGE_TYPES = {"png", "jpeg", "gif", "webp"}
TEXT_TYPES = {"csv", "txt", "json"}

MIME = {
    "pdf": "application/pdf",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "csv": "text/csv", "txt": "text/plain", "json": "application/json",
    "png": "image/png", "jpeg": "image/jpeg", "gif": "image/gif", "webp": "image/webp",
}

EXT_TO_TYPE = {
    ".pdf": "pdf", ".docx": "docx", ".xlsx": "xlsx", ".csv": "csv", ".json": "json",
    ".txt": "txt", ".text": "txt", ".md": "txt", ".log": "txt",
    ".png": "png", ".jpg": "jpeg", ".jpeg": "jpeg", ".gif": "gif", ".webp": "webp",
}

_EXECUTABLE_MAGIC = (b"MZ", b"\x7fELF", b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"#!")
_ARCHIVE_MAGIC = (b"\x1f\x8b", b"BZh", b"7z\xbc\xaf\x27\x1c", b"Rar!", b"\xfd7zXZ", b"ustar")
_OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"   # legacy .doc/.xls/.ppt: macro-capable, not supported


@dataclass(frozen=True)
class Detected:
    kind: str
    mime: str


def _block(reason: str, detail: str, severity: Severity = "HIGH") -> Blocked:
    return Blocked(reason, [Finding(type=reason, severity=severity, detail=detail)])


def _looks_like_text(data: bytes) -> bool:
    sample = data[:65536]
    if b"\x00" in sample:
        return sample.startswith((b"\xff\xfe", b"\xfe\xff"))    # UTF-16 with BOM only
    controls = sum(1 for b in sample if b < 32 and b not in (9, 10, 13, 12))
    return controls / max(1, len(sample)) < 0.02


def extension_type(filename: str | None) -> str | None:
    if not filename:
        return None
    ext = os.path.splitext(filename.strip().lower())[1]
    return EXT_TO_TYPE.get(ext, f"?{ext}" if ext else None)


def sniff(data: bytes, claimed_name: str | None = None) -> Detected:
    """Return the detected type or raise Blocked. Order matters: reject dangerous content before classifying."""
    if not data:
        raise _block("empty_file", "file is empty", "LOW")
    head = data[:16]

    if head.startswith(_EXECUTABLE_MAGIC):
        raise _block("executable_content", "executable or script content")
    if head.startswith(_ARCHIVE_MAGIC) or data[257:262] == b"ustar":
        raise _block("unsupported_type", "archive formats are not accepted")
    if head.startswith(_OLE_MAGIC):
        raise _block("unsupported_type", "legacy Office (OLE) documents are not accepted; re-save as DOCX/XLSX without macros")

    kind: str | None = None
    if data.startswith(b"%PDF-"):
        kind = "pdf"
    elif data.startswith(b"\x89PNG\r\n\x1a\n"):
        kind = "png"
    elif data.startswith(b"\xff\xd8\xff"):
        kind = "jpeg"
    elif data.startswith((b"GIF87a", b"GIF89a")):
        kind = "gif"
    elif data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        kind = "webp"
    elif data.startswith((b"PK\x03\x04", b"PK\x05\x06")):
        zf = open_safe(data, ZipLimits())
        names = set(zf.namelist())
        if "[Content_Types].xml" not in names:
            raise _block("unsupported_type", "ZIP archive that is not an Office document")
        if "word/document.xml" in names:
            kind = "docx"
        elif "xl/workbook.xml" in names:
            kind = "xlsx"
        else:
            raise _block("unsupported_type", "Office format not supported (only DOCX and XLSX)")
    elif _looks_like_text(data):
        claimed = extension_type(claimed_name)
        if claimed == "json":
            kind = "json"
            try:
                json.loads(data.decode("utf-8-sig", errors="strict"))
            except (ValueError, RecursionError, UnicodeDecodeError):
                raise _block("extension_mismatch", "declared .json but content is not valid JSON") from None
        elif claimed == "csv":
            kind = "csv"
        elif claimed in (None, "txt"):
            kind = "txt"
        else:
            # A text body under a non-text extension (.exe/.png/.pdf/unknown): mismatch or unsupported.
            raise _block("extension_mismatch" if claimed and not claimed.startswith("?") else "unsupported_type",
                         "text content does not match the declared file type")
    else:
        raise _block("unsupported_type", "binary content of an unrecognised format")

    claimed = extension_type(claimed_name)
    if claimed is not None:
        if claimed.startswith("?"):
            raise _block("unsupported_type", "file extension is not on the allow-list")
        if claimed != kind and not (claimed in TEXT_TYPES and kind in TEXT_TYPES):
            raise _block("extension_mismatch", "file content does not match its extension")
    return Detected(kind, MIME[kind])
