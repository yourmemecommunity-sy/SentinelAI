import io
import struct
import zipfile

import pytest

import samples
from app.file_validation.images import image_dimensions
from app.file_validation.safe_zip import ZipLimits, ZipReader, open_safe
from app.file_validation.sniff import sniff
from app.models import Blocked


def kind(data: bytes, name: str | None = None) -> str:
    return sniff(data, name).kind


def reason(data: bytes, name: str | None = None) -> str:
    with pytest.raises(Blocked) as ei:
        sniff(data, name)
    return ei.value.reason


class TestSniff:
    def test_detects_every_allowed_type_by_content(self):
        assert kind(samples.pdf()) == "pdf"
        assert kind(samples.docx(["x"])) == "docx"
        assert kind(samples.xlsx(["x"])) == "xlsx"
        assert kind(samples.png()) == "png"
        assert kind(b"\xff\xd8\xff\xe0" + b"\x00" * 20) == "jpeg"
        assert kind(b"GIF89a" + b"\x00" * 20) == "gif"
        assert kind(b"RIFF\x00\x00\x00\x00WEBPVP8 " + b"\x00" * 20) == "webp"
        assert kind(b"a,b,c\n1,2,3\n", "data.csv") == "csv"
        assert kind(b'{"a": 1}', "x.json") == "json"
        assert kind(b"plain text") == "txt"
        assert kind(b"plain text", "notes.txt") == "txt"

    def test_content_wins_over_the_name(self):
        assert kind(samples.pdf(), "innocent.pdf") == "pdf"
        assert reason(samples.pdf(), "report.txt") == "extension_mismatch"
        assert reason(samples.png(), "photo.jpg") == "extension_mismatch"
        assert reason(samples.docx(["x"]), "sheet.xlsx") == "extension_mismatch"
        assert reason(b"just text", "doc.pdf") == "extension_mismatch"

    @pytest.mark.parametrize("payload,name", [
        (b"MZ\x90\x00" + b"\x00" * 60, "notes.txt"), (b"\x7fELF\x02\x01\x01" + b"\x00" * 20, "img.png"),
        (b"#!/bin/sh\nrm -rf /\n", "run.txt"), (b"\xcf\xfa\xed\xfe" + b"\x00" * 20, "a.pdf"), (b"\xca\xfe\xba\xbe" + b"\x00" * 20, None),
    ])
    def test_executables_and_scripts_are_blocked_whatever_they_are_called(self, payload, name):
        assert reason(payload, name) == "executable_content"

    def test_archives_legacy_office_and_unknown_binaries_are_blocked(self):
        assert reason(b"\x1f\x8b\x08" + b"\x00" * 20) == "unsupported_type"                      # gzip
        assert reason(b"Rar!\x1a\x07\x00" + b"\x00" * 20) == "unsupported_type"
        assert reason(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 100, "old.doc") == "unsupported_type"   # OLE: macro-capable
        assert reason(bytes(range(256)) * 4) == "unsupported_type"
        plain_zip = samples._zip({"a.txt": "hello"})
        assert reason(plain_zip, "a.zip") == "unsupported_type"
        pptx = samples._zip({"[Content_Types].xml": samples.CT.format(extra=""), "ppt/presentation.xml": "<p/>"})
        assert reason(pptx, "deck.pptx") == "unsupported_type"

    def test_extension_allow_list_and_empty_files(self):
        assert reason(b"text body", "script.ps1") == "unsupported_type"
        assert reason(b"text body", "archive.zip") == "unsupported_type"
        assert reason(b"", "empty.txt") == "empty_file"

    def test_json_must_actually_be_json(self):
        assert reason(b"{not json", "x.json") == "extension_mismatch"

    def test_binary_masquerading_as_text_is_rejected(self):
        assert reason(b"hello\x00\x01\x02\x03world" * 10, "x.txt") == "unsupported_type"

    def test_utf16_text_with_bom_is_accepted(self):
        assert kind("héllo".encode("utf-16"), "u.txt") == "txt"


class TestZipSafety:
    def test_normal_ooxml_opens(self):
        assert "word/document.xml" in open_safe(samples.docx(["x"])).namelist()

    def test_corrupt_zip_is_blocked(self):
        with pytest.raises(Blocked) as ei:
            open_safe(b"PK\x03\x04" + b"garbage" * 20)
        assert ei.value.reason == "parse_error"

    def test_zip_bomb_by_ratio_is_blocked(self):
        big = samples._zip({"[Content_Types].xml": samples.CT.format(extra=""), "word/document.xml": "A" * (30 * 1024 * 1024)})
        assert len(big) < 200_000
        with pytest.raises(Blocked) as ei:
            open_safe(big)
        assert ei.value.reason == "zip_bomb"

    def test_too_many_entries_and_duplicate_names_are_blocked(self):
        with pytest.raises(Blocked) as ei:
            open_safe(samples._zip({f"f{i}.xml": "x" for i in range(30)}), ZipLimits(max_entries=10))
        assert ei.value.reason == "zip_anomaly"
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("word/document.xml", "<a/>")
            with pytest.warns(UserWarning):
                z.writestr("word/document.xml", "<b/>")        # duplicate name: AV and parser could disagree
        with pytest.raises(Blocked) as ei:
            open_safe(buf.getvalue())
        assert ei.value.reason == "zip_anomaly"

    @pytest.mark.parametrize("name", ["../evil.xml", "/etc/passwd", "a/../../b", "C:/x.xml"])
    def test_path_traversal_names_are_blocked(self, name):
        with pytest.raises(Blocked) as ei:
            open_safe(samples._zip({"[Content_Types].xml": "<x/>", name: "x"}))
        assert ei.value.reason == "zip_anomaly"

    def test_encrypted_members_are_blocked(self):
        data = bytearray(samples._zip({"word/document.xml": "<a/>"}))
        # set the "encrypted" general-purpose flag bit in both the local header and the central directory entry
        for sig in (b"PK\x03\x04", b"PK\x01\x02"):
            i = data.find(sig)
            off = i + (6 if sig == b"PK\x03\x04" else 8)
            data[off] |= 0x1
        with pytest.raises(Blocked) as ei:
            open_safe(bytes(data))
        assert ei.value.reason == "encrypted_document"

    def test_reads_are_capped_even_when_headers_lie(self):
        zf = open_safe(samples._zip({"[Content_Types].xml": "x", "a.xml": "A" * 5000}))
        with pytest.raises(Blocked) as ei:
            ZipReader(zf, ZipLimits(max_member_bytes=1000)).read("a.xml")
        assert ei.value.reason == "zip_bomb"
        r = ZipReader(zf, ZipLimits(max_total_bytes=6000))
        r.read("a.xml")
        with pytest.raises(Blocked):
            r.read("a.xml")                                           # shared budget exhausted


class TestImageHeaders:
    def test_png_dimensions_and_bomb_claims(self):
        assert image_dimensions("png", samples.png(3, 5)) == (3, 5)
        assert image_dimensions("png", samples.png_claiming(60000, 60000)) == (60000, 60000)

    def test_gif_and_jpeg(self):
        assert image_dimensions("gif", b"GIF89a" + struct.pack("<HH", 7, 9) + b"\x00" * 10) == (7, 9)
        jpeg = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00" + b"\xff\xc0\x00\x11\x08" + struct.pack(">HH", 40, 30) + b"\x03" + b"\x00" * 10
        assert image_dimensions("jpeg", jpeg) == (30, 40)

    def test_truncated_headers_are_blocked_not_crashed(self):
        for k, data in (("png", b"\x89PNG\r\n\x1a\n\x00\x00"), ("gif", b"GIF89a\x01"), ("jpeg", b"\xff\xd8\xff"), ("webp", b"RIFF\x00\x00\x00\x00WEBPVP8 ")):
            with pytest.raises(Blocked):
                image_dimensions(k, data)
