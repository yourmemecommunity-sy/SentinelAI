"""DOCX / XLSX extraction.

Goals: (1) extract EVERYTHING a model could later be shown - including hidden text, comments, headers/footers, metadata,
hyperlink targets, tracked deletions, hidden sheets - because hidden content is the standard vehicle for indirect prompt
injection; (2) BLOCK active or external content (macros, embedded objects, OLE/template/DDE references).
XML is parsed with defusedxml (no DTDs, no entity expansion, no external entities) inside a size-capped ZIP.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from xml.etree.ElementTree import Element

from defusedxml import ElementTree as DET
from defusedxml.common import DefusedXmlException

from app.file_validation.safe_zip import ZipLimits, ZipReader, open_safe
from app.models import Blocked, Finding
from app.parsers.budget import Budget

W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
S = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
REL = "{http://schemas.openxmlformats.org/package/2006/relationships}"
DC = "{http://purl.org/dc/elements/1.1/}"
CP = "{http://schemas.openxmlformats.org/package/2006/metadata/core-properties}"
DCTERMS = "{http://purl.org/dc/terms/}"

_ACTIVE_NAME = re.compile(r"(^|/)(vbaProject\.bin|vbaData\.xml)$|/activeX/|/embeddings/|/oleObject\d*\.bin$", re.I)
_DDE = re.compile(r"\b(DDEAUTO|DDE|INCLUDETEXT|INCLUDEPICTURE|IMPORTXML)\b|cmd\s*\||powershell|/c\s+calc", re.I)
_BLOCK_REL = ("oleobject", "attachedtemplate", "externallinkpath", "frame", "subdocument", "package")


def _xml(b: bytes) -> Element:
    try:
        root: Element = DET.fromstring(b, forbid_dtd=True)
        return root
    except DefusedXmlException:
        raise Blocked("xml_attack", [Finding(type="xml_attack", severity="CRITICAL", detail="DTD/entity/external-entity constructs are forbidden")]) from None
    except (ET.ParseError, ValueError, RecursionError):
        raise Blocked("parse_error", [Finding(type="malformed_xml", severity="MEDIUM", detail="XML part could not be parsed")]) from None


def _guard_package(r: ZipReader, findings: list[Finding]) -> None:
    for name in r.names:
        if _ACTIVE_NAME.search(name):
            raise Blocked("macros_present" if "vba" in name.lower() else "embedded_objects",
                          [Finding(type="active_content", severity="CRITICAL", detail=f"package contains {name.rsplit('/', 1)[-1]}")])
    ct = r.read("[Content_Types].xml") if "[Content_Types].xml" in r.names else b""
    if b"macroEnabled" in ct:
        raise Blocked("macros_present", [Finding(type="active_content", severity="CRITICAL", detail="macro-enabled document type")])

    for name in r.names:
        if not name.endswith(".rels"):
            continue
        for rel in _xml(r.read(name)).iter(f"{REL}Relationship"):
            mode, typ = rel.get("TargetMode", ""), rel.get("Type", "").rsplit("/", 1)[-1].lower()
            if mode != "External":
                continue
            if typ in _BLOCK_REL:
                raise Blocked("external_reference", [Finding(type="external_reference", severity="CRITICAL", detail=f"external {typ} relationship")])
            findings.append(Finding(type="external_hyperlink" if typ == "hyperlink" else "external_resource",
                                    severity="INFO" if typ == "hyperlink" else "MEDIUM", detail=f"external {typ} reference"))


def _metadata(r: ZipReader, budget: Budget, out: list[str]) -> None:
    if "docProps/core.xml" not in r.names:
        return
    root = _xml(r.read("docProps/core.xml"))
    for tag in (f"{DC}title", f"{DC}subject", f"{DC}creator", f"{DC}description", f"{CP}keywords", f"{CP}lastModifiedBy", f"{CP}category"):
        el = root.find(tag)
        if el is not None and el.text and el.text.strip():
            out.append(budget.add(f"[metadata:{tag.rsplit('}', 1)[-1]}] {el.text.strip()}"))


def _relationship_targets(r: ZipReader, rels_name: str) -> dict[str, str]:
    if rels_name not in r.names:
        return {}
    return {rel.get("Id", ""): rel.get("Target", "") for rel in _xml(r.read(rels_name)).iter(f"{REL}Relationship")
            if rel.get("TargetMode") == "External"}


# ------------------------------------------------------------------ DOCX
def _run_hidden(rpr: Element | None) -> bool:
    if rpr is None:
        return False
    v = rpr.find(f"{W}vanish")
    if v is not None and v.get(f"{W}val", "true").lower() not in ("0", "false", "off"):
        return True
    if rpr.find(f"{W}webHidden") is not None:
        return True
    sz = rpr.find(f"{W}sz")
    size = sz.get(f"{W}val", "") if sz is not None else ""
    if size.isdigit() and int(size) <= 2:      # <= 1pt
        return True
    color = rpr.find(f"{W}color")
    return color is not None and color.get(f"{W}val", "").upper() == "FFFFFF"


def extract_docx(data: bytes, budget: Budget, limits: ZipLimits = ZipLimits()) -> tuple[str, list[Finding]]:
    r = ZipReader(open_safe(data, limits), limits)
    findings: list[Finding] = []
    _guard_package(r, findings)

    out: list[str] = []
    hidden_runs = deleted_runs = 0
    part_re = re.compile(r"word/(document|header\d*|footer\d*|footnotes|endnotes|comments)\.xml$")
    for name in sorted(n for n in r.names if part_re.fullmatch(n)):
        links = _relationship_targets(r, name.replace("word/", "word/_rels/") + ".rels")
        for p in _xml(r.read(name)).iter(f"{W}p"):
            buf: list[str] = []
            for run in p.iter(f"{W}r"):
                piece: list[str] = []
                for el in run:
                    if el.tag == f"{W}t" and el.text:
                        piece.append(el.text)
                    elif el.tag == f"{W}delText" and el.text:
                        piece.append(el.text)
                        deleted_runs += 1
                    elif el.tag == f"{W}instrText" and el.text:
                        if _DDE.search(el.text):
                            raise Blocked("active_content", [Finding(type="field_code_attack", severity="CRITICAL", detail="dangerous Word field code (DDE/INCLUDE)")])
                        piece.append(el.text)              # field instructions can carry URLs/instructions: scan them
                    elif el.tag == f"{W}tab":
                        piece.append("\t")
                    elif el.tag == f"{W}br":
                        piece.append("\n")
                s = "".join(piece)
                if s and _run_hidden(run.find(f"{W}rPr")):
                    hidden_runs += 1
                buf.append(s)
            for h in p.iter(f"{W}hyperlink"):
                rid = h.get("{http://schemas.openxmlformats.org/officeDocument/2006/relationships}id", "")
                if rid in links:
                    buf.append(f" [link] {links[rid]}")
            line = "".join(buf)
            if line.strip():
                out.append(budget.add(line))
    _metadata(r, budget, out)

    if hidden_runs:
        findings.append(Finding(type="hidden_text", severity="HIGH", detail=f"{hidden_runs} hidden run(s) (hidden/tiny/white text); included in the scan"))
    if deleted_runs:
        findings.append(Finding(type="tracked_deletions", severity="MEDIUM", detail=f"{deleted_runs} deleted run(s) still present in the file; included in the scan"))
    return "\n".join(out), findings


# ------------------------------------------------------------------ XLSX
def _text_of(el: Element, tag: str) -> str:
    return "".join(t.text or "" for t in el.iter(tag))


def extract_xlsx(data: bytes, budget: Budget, limits: ZipLimits = ZipLimits(), max_cells: int = 5_000_000) -> tuple[str, list[Finding]]:
    r = ZipReader(open_safe(data, limits), limits)
    findings: list[Finding] = []
    _guard_package(r, findings)
    names = set(r.names)
    out: list[str] = []

    if "xl/workbook.xml" in names:
        wb = _xml(r.read("xl/workbook.xml"))
        hidden = [s for s in wb.iter(f"{S}sheet") if s.get("state") in ("hidden", "veryHidden")]
        for s in wb.iter(f"{S}sheet"):
            out.append(budget.add(f"[sheet] {s.get('name', '')}"))
        for dn in wb.iter(f"{S}definedName"):
            out.append(budget.add(f"[name:{dn.get('name', '')}] {dn.text or ''}"))
        if hidden:
            findings.append(Finding(type="hidden_sheet", severity="HIGH", detail=f"{len(hidden)} hidden sheet(s); included in the scan"))
    if any(n.startswith("xl/externalLinks/") for n in names):
        findings.append(Finding(type="external_links", severity="MEDIUM", detail="workbook links to external workbooks"))

    if "xl/sharedStrings.xml" in names:
        for si in _xml(r.read("xl/sharedStrings.xml")).iter(f"{S}si"):
            t = _text_of(si, f"{S}t")
            if t:
                out.append(budget.add(t))

    cells = 0
    for name in sorted(n for n in names if re.fullmatch(r"xl/worksheets/sheet\d+\.xml", n)):
        for c in _xml(r.read(name)).iter(f"{S}c"):
            cells += 1
            if cells > max_cells:
                raise Blocked("text_too_large", [Finding(type="text_too_large", severity="MEDIUM", detail="too many cells")])
            f = c.find(f"{S}f")
            if f is not None and f.text:
                if _DDE.search(f.text):
                    raise Blocked("active_content", [Finding(type="formula_attack", severity="CRITICAL", detail="dangerous formula (DDE/command)")])
                out.append(budget.add(f"={f.text}"))
            if c.get("t") == "inlineStr":
                t = _text_of(c, f"{S}t")
                if t:
                    out.append(budget.add(t))
            elif c.get("t") != "s":                      # "s" cells index sharedStrings, already extracted in full
                v = c.find(f"{S}v")
                if v is not None and v.text:
                    out.append(budget.add(v.text))       # numbers count too (card numbers stored as numeric cells)
    for name in sorted(n for n in names if re.fullmatch(r"xl/(comments\d*|threadedComments/[^/]+)\.xml", n)):
        t = _text_of(_xml(r.read(name)), f"{S}t") or " ".join((e.text or "") for e in _xml(r.read(name)).iter() if e.tag.endswith("}text"))
        if t.strip():
            out.append(budget.add(f"[comment] {t}"))
    _metadata(r, budget, out)
    return "\n".join(out), findings
