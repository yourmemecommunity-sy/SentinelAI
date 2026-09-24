"""Hardened ZIP access for OOXML (DOCX/XLSX): bounded sizes, no encrypted members, no duplicate/odd names.

Header-declared sizes can lie, so reads are ALSO capped (a member is read with `limit + 1` and rejected if it overflows).
"""
from __future__ import annotations

import io
import zipfile
from dataclasses import dataclass

from app.models import Blocked, Finding


@dataclass(frozen=True)
class ZipLimits:
    max_entries: int = 2000
    max_total_bytes: int = 200 * 1024 * 1024
    max_member_bytes: int = 100 * 1024 * 1024
    max_ratio: int = 200          # uncompressed / compressed, applied to members > 1 MiB
    ratio_floor: int = 1024 * 1024


def _bad(reason: str, detail: str) -> Blocked:
    return Blocked(reason, [Finding(type=reason, severity="HIGH", detail=detail)])


def open_safe(data: bytes, limits: ZipLimits = ZipLimits()) -> zipfile.ZipFile:
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, ValueError, OSError):
        raise Blocked("parse_error", [Finding(type="corrupt_archive", severity="MEDIUM", detail="not a readable ZIP container")]) from None

    infos = zf.infolist()
    if len(infos) > limits.max_entries:
        raise _bad("zip_anomaly", f"{len(infos)} entries exceeds limit {limits.max_entries}")
    seen: set[str] = set()
    total = 0
    for i in infos:
        name = i.filename
        if name in seen:
            # Duplicate names make different tools see different content (AV vs parser): "zip confusion".
            raise _bad("zip_anomaly", "duplicate member names")
        seen.add(name)
        if name.startswith(("/", "\\")) or ".." in name.replace("\\", "/").split("/") or ":" in name.split("/")[0]:
            raise _bad("zip_anomaly", "member path escapes the archive root")
        if i.flag_bits & 0x1:
            raise Blocked("encrypted_document", [Finding(type="encrypted_document", severity="HIGH", detail="encrypted ZIP member")])
        if i.file_size > limits.max_member_bytes:
            raise _bad("zip_bomb", "member exceeds size limit")
        if i.file_size > limits.ratio_floor and i.compress_size > 0 and i.file_size / i.compress_size > limits.max_ratio:
            raise _bad("zip_bomb", "suspicious compression ratio")
        total += i.file_size
    if total > limits.max_total_bytes:
        raise _bad("zip_bomb", "total uncompressed size exceeds limit")
    return zf


class ZipReader:
    """Reads members under a shared byte budget so the sum of all reads is bounded, whatever the headers claim."""

    def __init__(self, zf: zipfile.ZipFile, limits: ZipLimits = ZipLimits()) -> None:
        self.zf = zf
        self.limits = limits
        self._budget = limits.max_total_bytes

    @property
    def names(self) -> list[str]:
        return self.zf.namelist()

    def read(self, name: str) -> bytes:
        cap = min(self.limits.max_member_bytes, self._budget)
        try:
            with self.zf.open(name) as f:
                buf = f.read(cap + 1)
        except (KeyError, zipfile.BadZipFile, RuntimeError, OSError, EOFError):
            raise Blocked("parse_error", [Finding(type="corrupt_archive", severity="MEDIUM", detail="unreadable member")]) from None
        if len(buf) > cap:
            raise _bad("zip_bomb", "member expands beyond the read budget")
        self._budget -= len(buf)
        return buf
