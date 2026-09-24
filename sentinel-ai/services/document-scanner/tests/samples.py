"""Builders for REAL (structurally valid) sample files, benign and hostile. Everything is generated at runtime from
synthetic content; no binary fixtures are committed and no secret-shaped literals appear in source."""
from __future__ import annotations

import io
import struct
import zipfile
import zlib

CT = '<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/>{extra}</Types>'
W_NS = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"'
S_NS = 'xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"'
REL_NS = "http://schemas.openxmlformats.org/package/2006/relationships"


def _zip(files: dict[str, str | bytes], *, compress: int = zipfile.ZIP_DEFLATED) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compress) as z:
        for name, content in files.items():
            z.writestr(name, content)
    return buf.getvalue()


def run(text: str, *, hidden: bool = False, vanish: bool = False, white: bool = False, tiny: bool = False, deleted: str | None = None) -> str:
    rpr = ""
    if hidden or vanish:
        rpr += "<w:vanish/>"
    if white:
        rpr += '<w:color w:val="FFFFFF"/>'
    if tiny:
        rpr += '<w:sz w:val="2"/>'
    inner = f"<w:delText>{deleted}</w:delText>" if deleted is not None else f"<w:t>{text}</w:t>"
    return f"<w:r>{f'<w:rPr>{rpr}</w:rPr>' if rpr else ''}{inner}</w:r>"


def docx(paragraphs: list[str] | None = None, *, runs: list[str] | None = None, extra: dict[str, str | bytes] | None = None,
         content_types_extra: str = "", core: str | None = None, rels: str | None = None, header: str | None = None,
         comments: str | None = None, document_xml: str | None = None) -> bytes:
    body = "".join(f"<w:p>{run(p)}</w:p>" for p in (paragraphs or [])) + "".join(f"<w:p>{r}</w:p>" for r in (runs or []))
    files: dict[str, str | bytes] = {
        "[Content_Types].xml": CT.format(extra=content_types_extra),
        "word/document.xml": document_xml or f'<?xml version="1.0"?><w:document {W_NS}><w:body>{body}</w:body></w:document>',
    }
    if core:
        files["docProps/core.xml"] = (f'<?xml version="1.0"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
                                      f'xmlns:dc="http://purl.org/dc/elements/1.1/">{core}</cp:coreProperties>')
    if rels:
        files["word/_rels/document.xml.rels"] = f'<?xml version="1.0"?><Relationships xmlns="{REL_NS}">{rels}</Relationships>'
    if header:
        files["word/header1.xml"] = f'<?xml version="1.0"?><w:hdr {W_NS}><w:p>{run(header)}</w:p></w:hdr>'
    if comments:
        files["word/comments.xml"] = f'<?xml version="1.0"?><w:comments {W_NS}><w:comment><w:p>{run(comments)}</w:p></w:comment></w:comments>'
    files.update(extra or {})
    return _zip(files)


def xlsx(shared: list[str] | None = None, cells: list[tuple[str, str, str]] | None = None, *, sheets: list[tuple[str, str]] | None = None,
         extra: dict[str, str | bytes] | None = None, formulas: list[str] | None = None, comments: str | None = None) -> bytes:
    """cells: (type, value, unused) with type in {"n","s","inlineStr"}."""
    sst = "".join(f"<si><t>{s}</t></si>" for s in (shared or []))
    rows = ""
    for i, (t, v, _) in enumerate(cells or [], 1):
        rows += (f'<row r="{i}"><c r="A{i}" t="inlineStr"><is><t>{v}</t></is></c></row>' if t == "inlineStr"
                 else f'<row r="{i}"><c r="A{i}" t="{t}"><v>{v}</v></c></row>')
    for j, f in enumerate(formulas or [], 100):
        rows += f'<row r="{j}"><c r="A{j}"><f>{f}</f></c></row>'
    sheet_xml = "".join(f'<sheet name="{n}" sheetId="{k}" state="{st}" r:id="rId{k}"/>' for k, (n, st) in enumerate(sheets or [("Sheet1", "visible")], 1))
    files: dict[str, str | bytes] = {
        "[Content_Types].xml": CT.format(extra=""),
        "xl/workbook.xml": f'<?xml version="1.0"?><workbook {S_NS} xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>{sheet_xml}</sheets></workbook>',
        "xl/worksheets/sheet1.xml": f'<?xml version="1.0"?><worksheet {S_NS}><sheetData>{rows}</sheetData></worksheet>',
        "xl/sharedStrings.xml": f'<?xml version="1.0"?><sst {S_NS}>{sst}</sst>',
    }
    if comments:
        files["xl/comments1.xml"] = f'<?xml version="1.0"?><comments {S_NS}><commentList><comment ref="A1"><text><r><t>{comments}</t></r></text></comment></commentList></comments>'
    files.update(extra or {})
    return _zip(files)


def pdf(text: str = "Hello world", *, extra_objects: str = "", catalog_extra: str = "", page_extra: str = "", pages: int = 1) -> bytes:
    """A minimal, valid text PDF built by hand (xref computed). `extra_objects` are raw object bodies numbered from 10."""
    stream = f"BT /F1 12 Tf 72 720 Td ({text.replace(chr(92), chr(92) * 2).replace('(', chr(92) + '(').replace(')', chr(92) + ')')}) Tj ET".encode("latin-1", "replace")
    objs: dict[int, bytes] = {
        1: f"<< /Type /Catalog /Pages 2 0 R {catalog_extra} >>".encode(),
        2: ("<< /Type /Pages /Kids [" + " ".join(f"{3 + 2 * k} 0 R" for k in range(pages)) + f"] /Count {pages} >>").encode(),
        9: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    }
    for k in range(pages):
        objs[3 + 2 * k] = (f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents {4 + 2 * k} 0 R /Resources << /Font << /F1 9 0 R >> >> {page_extra} >>").encode()
        objs[4 + 2 * k] = b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream"
    n = 10
    for body in [b for b in extra_objects.split("|||") if b.strip()]:
        objs[n] = body.encode()
        n += 1
    out = io.BytesIO()
    out.write(b"%PDF-1.4\n")
    offsets: dict[int, int] = {}
    for num in sorted(objs):
        offsets[num] = out.tell()
        out.write(f"{num} 0 obj\n".encode() + objs[num] + b"\nendobj\n")
    xref = out.tell()
    size = max(objs) + 1
    out.write(f"xref\n0 {size}\n".encode() + b"0000000000 65535 f \n")
    for num in range(1, size):
        out.write((f"{offsets[num]:010d} 00000 n \n" if num in offsets else "0000000000 65535 f \n").encode())
    out.write(f"trailer\n<< /Size {size} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode())
    return out.getvalue()


def png(width: int = 2, height: int = 2) -> bytes:
    def chunk(t: bytes, d: bytes) -> bytes:
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)
    raw = b"".join(b"\x00" + b"\xff\xff\xff" * width for _ in range(height))
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)) + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b"")


def png_claiming(width: int, height: int) -> bytes:
    """A PNG whose HEADER claims huge dimensions (decompression-bomb probe); the pixel data is tiny."""
    real = png(1, 1)
    return real[:16] + struct.pack(">II", width, height) + real[24:]


def pdf_objstm(text: str = "Hello objstm", *, js: bool = False) -> bytes:
    """A PDF 1.5 whose catalog/pages/page/font (and optionally a JavaScript action) live in a Flate-COMPRESSED object
    stream addressed by an xref stream. A raw byte search cannot see names inside it; only a parsed-object walk can."""
    inner: dict[int, str] = {
        1: f"<< /Type /Catalog /Pages 2 0 R {'/OpenAction 10 0 R' if js else ''} >>",
        2: "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        3: "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 9 0 R >> >> >>",
        9: "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    }
    if js:
        inner[10] = r"<< /S /JavaScript /JS (app.alert\(1\)) >>"
    nums = sorted(inner)
    bodies = [inner[n].encode() for n in nums]
    header = b""
    off = 0
    for n, b in zip(nums, bodies):
        header += f"{n} {off} ".encode()
        off += len(b) + 1
    objstm_raw = zlib.compress(header + b"\n".join(bodies))
    content = f"BT /F1 12 Tf 72 720 Td ({text}) Tj ET".encode()

    out = io.BytesIO()
    out.write(b"%PDF-1.5\n")
    o4 = out.tell()
    out.write(b"4 0 obj\n<< /Length %d >>\nstream\n" % len(content) + content + b"\nendstream\nendobj\n")
    o20 = out.tell()
    out.write(b"20 0 obj\n<< /Type /ObjStm /N %d /First %d /Length %d /Filter /FlateDecode >>\nstream\n" % (len(nums), len(header), len(objstm_raw))
              + objstm_raw + b"\nendstream\nendobj\n")
    o21 = out.tell()
    rows = b""
    for n in range(22):
        if n in inner:
            rows += struct.pack(">BIH", 2, 20, nums.index(n))
        elif n == 4:
            rows += struct.pack(">BIH", 1, o4, 0)
        elif n == 20:
            rows += struct.pack(">BIH", 1, o20, 0)
        elif n == 21:
            rows += struct.pack(">BIH", 1, o21, 0)
        else:
            rows += struct.pack(">BIH", 0, 0, 0)
    xref_raw = zlib.compress(rows)
    out.write(b"21 0 obj\n<< /Type /XRef /Size 22 /W [1 4 2] /Root 1 0 R /Length %d /Filter /FlateDecode >>\nstream\n" % len(xref_raw)
              + xref_raw + b"\nendstream\nendobj\n")
    out.write(f"startxref\n{o21}\n%%EOF\n".encode())
    return out.getvalue()
