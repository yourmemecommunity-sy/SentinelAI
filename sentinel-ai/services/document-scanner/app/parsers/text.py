"""Plain text, CSV and JSON extraction (standard library only, iterative - no recursion on attacker-controlled depth)."""
from __future__ import annotations

import csv
import io
import json

from app.models import Blocked, Finding
from app.parsers.budget import Budget

MAX_JSON_NODES = 2_000_000
MAX_CSV_ROWS = 2_000_000


def decode_text(data: bytes) -> tuple[str, list[Finding]]:
    findings: list[Finding] = []
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            return data.decode("utf-16"), findings
        except UnicodeDecodeError:
            raise Blocked("parse_error", [Finding(type="bad_encoding", severity="MEDIUM", detail="invalid UTF-16")]) from None
    try:
        return data.decode("utf-8-sig"), findings
    except UnicodeDecodeError:
        # Legacy 8-bit text: decode leniently so it is still scanned, and say so.
        findings.append(Finding(type="non_utf8_encoding", severity="INFO", detail="decoded as Windows-1252"))
        return data.decode("cp1252", errors="replace"), findings


def extract_txt(data: bytes, budget: Budget) -> tuple[str, list[Finding]]:
    text, findings = decode_text(data)
    return budget.add(text), findings


def extract_csv(data: bytes, budget: Budget) -> tuple[str, list[Finding]]:
    text, findings = decode_text(data)
    csv.field_size_limit(1_000_000)
    out: list[str] = []
    try:
        for n, row in enumerate(csv.reader(io.StringIO(text, newline=""))):
            if n >= MAX_CSV_ROWS:
                raise Blocked("text_too_large", [Finding(type="text_too_large", severity="MEDIUM", detail="too many CSV rows")])
            out.append(budget.add("\t".join(row)))
    except csv.Error:
        # Malformed CSV: fall back to the raw text so nothing escapes inspection.
        findings.append(Finding(type="malformed_csv", severity="INFO", detail="scanned as plain text"))
        budget.used = 0
        return budget.add(text), findings
    return "\n".join(out), findings


def extract_json(data: bytes, budget: Budget) -> tuple[str, list[Finding]]:
    text, findings = decode_text(data)
    try:
        root = json.loads(text)
    except (ValueError, RecursionError):
        raise Blocked("parse_error", [Finding(type="invalid_json", severity="MEDIUM", detail="not valid JSON (or nested too deeply)")]) from None

    lines: list[str] = []
    stack: list[tuple[str, object]] = [("", root)]
    nodes = 0
    while stack:
        path, node = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES:
            raise Blocked("text_too_large", [Finding(type="text_too_large", severity="MEDIUM", detail="JSON too large")])
        if isinstance(node, dict):
            for k, v in node.items():
                lines.append(budget.add(str(k)))          # keys can carry data (e.g. {"jane@x.com": 1}) and instructions
                stack.append((f"{path}.{k}", v))
        elif isinstance(node, list):
            stack.extend((f"{path}[]", v) for v in node)
        elif node is not None:
            lines.append(budget.add(f"{path.rsplit('.', 1)[-1]}: {node}" if path else str(node)))   # numbers count: card numbers as ints
    return "\n".join(lines), findings
