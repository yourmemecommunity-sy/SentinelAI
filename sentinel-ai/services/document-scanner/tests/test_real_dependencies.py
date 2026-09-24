"""Verification against the REAL OCR engine and the REAL antivirus daemon.

Everything else in this suite uses the development stand-ins (an EICAR-string matcher, and no OCR at all). Those prove the
fail-closed wiring but cannot prove the service works with the dependencies it will actually have in production. These tests
run only when the real ones are present:

  * Tesseract: found on PATH (or TESSERACT_CMD).
  * clamd: reachable at CLAMD_HOST/CLAMD_PORT.

On a machine without them the module skips, and the suite's coverage claim stays honest.
Run inside WSL (see scripts/development/wsl-infra.sh) where both are installed:
    /opt/dsvenv/bin/python -m pytest tests/test_real_dependencies.py -q
"""
from __future__ import annotations

import io
import os
import shutil
import socket

import pytest

from app.config.settings import Settings
from app.malware.scanners import EICAR, ClamdScanner, EicarScanner, build_scanner
from app.models import Blocked
from app.ocr.engine import TesseractOcr, build_ocr
from app.pipelines.extract_pipeline import ExtractPipeline

CLAMD_HOST = os.environ.get("CLAMD_HOST", "127.0.0.1")
CLAMD_PORT = int(os.environ.get("CLAMD_PORT", "3310"))
TESSERACT = os.environ.get("TESSERACT_CMD") or shutil.which("tesseract")


def _clamd_up() -> bool:
    try:
        with socket.create_connection((CLAMD_HOST, CLAMD_PORT), timeout=3):
            return True
    except OSError:
        return False


HAVE_TESSERACT = bool(TESSERACT)
HAVE_CLAMD = _clamd_up()


def png_with_text(lines: list[str], size=(1100, 300)) -> bytes:
    """A real PNG containing rendered text, for the OCR engine to read back."""
    pytest.importorskip("PIL", reason="pillow is needed to render a test image")
    from PIL import Image, ImageDraw, ImageFont

    img = Image.new("RGB", size, "white")
    d = ImageDraw.Draw(img)
    font = None
    for path in ("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf"):
        if os.path.exists(path):
            font = ImageFont.truetype(path, 40)
            break
    y = 30
    for line in lines:
        d.text((30, y), line, fill="black", font=font)
        y += 60
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


# ------------------------------------------------------------------ real OCR
@pytest.mark.skipif(not HAVE_TESSERACT, reason="tesseract is not installed")
class TestRealTesseract:
    def test_reports_itself_available_and_reads_text_back_from_a_real_image(self):
        ocr = TesseractOcr(cmd=TESSERACT)
        assert ocr.available()
        text = ocr.extract(png_with_text(["Quarterly revenue summary"]), "image/png")
        assert "revenue" in text.lower()

    def test_text_hidden_in_an_IMAGE_is_recovered_so_it_can_be_scanned(self):
        """The point of OCR here: personal data and secrets pasted as a screenshot must not bypass the text scanners."""
        ocr = TesseractOcr(cmd=TESSERACT)
        text = ocr.extract(png_with_text(["Contact: jane.doe@example.com", "Ref 4111 1111 1111 1111"]), "image/png")
        low = text.lower().replace(" ", "")
        assert "jane.doe@example.com".replace(" ", "") in low
        assert "4111111111111111" in low

    def test_build_ocr_selects_the_real_engine_when_it_is_present(self):
        engine = build_ocr(TESSERACT)
        assert engine.name == "tesseract" and engine.available()

    def test_an_image_with_no_text_is_not_treated_as_a_failure(self):
        ocr = TesseractOcr(cmd=TESSERACT)
        assert ocr.extract(png_with_text([]), "image/png").strip() == ""

    def test_garbage_that_claims_to_be_an_image_fails_closed(self):
        ocr = TesseractOcr(cmd=TESSERACT)
        with pytest.raises(Blocked) as e:
            ocr.extract(b"\x89PNG\r\n\x1a\n" + b"not really an image" * 20, "image/png")
        assert e.value.reason == "ocr_failed"

    def test_full_pipeline_ocrs_a_real_image_through_the_isolated_child_process(self):
        settings = Settings(tesseract_cmd=TESSERACT, malware_scanner="eicar")
        pipeline = ExtractPipeline(settings, build_scanner(settings.malware_scanner, settings.clamd_host, settings.clamd_port), build_ocr(settings.tesseract_cmd))
        result = pipeline.run(png_with_text(["Invoice total 42 USD"]), ".png")
        assert result.verdict == "OK", result.block_reason
        assert "invoice" in result.text.lower()
        assert result.ocr_used is True


# ------------------------------------------------------------------ real antivirus
@pytest.mark.skipif(not HAVE_CLAMD, reason=f"clamd is not reachable at {CLAMD_HOST}:{CLAMD_PORT}")
class TestRealClamd:
    def scanner(self) -> ClamdScanner:
        return ClamdScanner(host=CLAMD_HOST, port=CLAMD_PORT, timeout=30.0)

    def test_the_daemon_is_reachable_and_healthy(self):
        assert self.scanner().healthy()

    def test_a_clean_file_passes(self):
        assert self.scanner().scan(b"an ordinary sentence in a text file").status == "clean"

    def test_the_EICAR_test_file_is_detected_by_the_REAL_engine(self):
        """The dev baseline only matches the raw EICAR bytes. This proves a real signature engine is in the path."""
        v = self.scanner().scan(EICAR)
        assert v.status == "infected"
        assert "eicar" in (v.signature or "").lower()

    def test_EICAR_hidden_inside_a_ZIP_is_detected_although_the_raw_bytes_never_appear(self):
        """The documented weakness of the dev scanner: compressed content is invisible to it. A real engine unpacks."""
        import zipfile

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("invoice.txt", EICAR)
        blob = buf.getvalue()
        assert EICAR not in blob                      # genuinely compressed, not stored verbatim
        assert self.scanner().scan(blob).status == "infected"

    def test_build_scanner_selects_clamd_and_the_pipeline_blocks_an_infected_upload(self):
        settings = Settings(malware_scanner="clamd", clamd_host=CLAMD_HOST, clamd_port=CLAMD_PORT, tesseract_cmd=TESSERACT)
        scanner = build_scanner(settings.malware_scanner, settings.clamd_host, settings.clamd_port)
        assert scanner.name == "clamd"
        pipeline = ExtractPipeline(settings, scanner, build_ocr(settings.tesseract_cmd))
        result = pipeline.run(EICAR, ".txt")
        assert result.verdict == "BLOCK"
        assert result.block_reason == "malware_detected"
        assert result.text == ""                       # nothing from an infected file is released

    def test_a_clean_upload_still_passes_through_the_real_scanner(self):
        settings = Settings(malware_scanner="clamd", clamd_host=CLAMD_HOST, clamd_port=CLAMD_PORT, tesseract_cmd=TESSERACT)
        pipeline = ExtractPipeline(settings, build_scanner(settings.malware_scanner, settings.clamd_host, settings.clamd_port), build_ocr(settings.tesseract_cmd))
        result = pipeline.run(b"Board minutes: revenue grew four percent.", ".txt")
        assert result.verdict == "OK"
        assert "revenue" in result.text

    def test_the_readiness_self_test_passes_with_the_real_engine(self):
        settings = Settings(malware_scanner="clamd", clamd_host=CLAMD_HOST, clamd_port=CLAMD_PORT)
        pipeline = ExtractPipeline(settings, build_scanner(settings.malware_scanner, settings.clamd_host, settings.clamd_port), build_ocr(settings.tesseract_cmd))
        assert pipeline.self_test() is True

    def test_pointing_at_a_dead_port_fails_closed_rather_than_passing_the_file(self):
        dead = ClamdScanner(host=CLAMD_HOST, port=1, timeout=2.0)
        assert not dead.healthy()
        assert dead.scan(b"x").status == "error"
        settings = Settings(malware_scanner="clamd", clamd_host=CLAMD_HOST, clamd_port=1)
        pipeline = ExtractPipeline(settings, dead, build_ocr(settings.tesseract_cmd))
        result = pipeline.run(b"harmless", ".txt")
        assert result.verdict == "BLOCK"
        assert result.block_reason in ("malware_scan_failed", "malware_detected")
        assert result.text == ""


    def test_EICAR_is_only_detected_as_a_WHOLE_file_which_limits_what_it_can_prove(self):
        """Measured against ClamAV 1.5.3: the EICAR signature matches only when the file IS the EICAR file. Prepend or
        append a single byte and the real engine reports clean.

        This is the EICAR standard behaving as specified, not a gap in SentinelAI, but it has two consequences worth
        pinning down so nobody later "fixes" a test by weakening the scanner:
          * EICAR cannot be used to simulate malware *embedded* in a document. Only a real signature can.
          * The development `EicarScanner` does a substring match, so it is MORE aggressive than real ClamAV here.
            A file that the dev stand-in blocks may legitimately pass a real engine.
        """
        s = self.scanner()
        assert s.scan(EICAR).status == "infected"
        for surrounded in (b"prefix\n" + EICAR, EICAR + b"\nsuffix", png_with_text(["x"]) + EICAR):
            assert s.scan(surrounded).status == "clean"
        assert EicarScanner().scan(b"prefix\n" + EICAR).status == "infected"      # the stand-in disagrees, by design


@pytest.mark.skipif(not (HAVE_TESSERACT and HAVE_CLAMD), reason="needs both real dependencies")
def test_an_infected_upload_is_stopped_before_the_real_OCR_engine_ever_runs():
    """Ordering: the antivirus runs before any parser or OCR. Proven with the real OCR engine present and a scanner that
    reports infected - real ClamAV cannot be made to flag a *valid image*, because EICAR only matches a whole file."""
    settings = Settings(malware_scanner="clamd", clamd_host=CLAMD_HOST, clamd_port=CLAMD_PORT, tesseract_cmd=TESSERACT)
    real_ocr = build_ocr(settings.tesseract_cmd)
    assert real_ocr.name == "tesseract"

    class CountingOcr:
        name = "tesseract"
        calls = 0

        def available(self) -> bool:
            return True

        def extract(self, data: bytes, mime: str) -> str:
            CountingOcr.calls += 1
            return real_ocr.extract(data, mime)

    class AlwaysInfected:
        name = "clamd"

        def scan(self, data: bytes):
            from app.malware.scanners import MalwareVerdict

            return MalwareVerdict("infected", "Test.Signature")

        def healthy(self) -> bool:
            return True

    ocr = CountingOcr()
    blocked = ExtractPipeline(settings, AlwaysInfected(), ocr).run(png_with_text(["invoice 42"]), ".png")
    assert blocked.verdict == "BLOCK"
    assert blocked.block_reason == "malware_detected"
    assert blocked.text == ""
    assert CountingOcr.calls == 0                       # the image never reached the OCR engine

    # ...and the same image with a clean verdict does reach it, so the counter is meaningful.
    ok = ExtractPipeline(settings, build_scanner("clamd", CLAMD_HOST, CLAMD_PORT), ocr).run(png_with_text(["invoice 42"]), ".png")
    assert ok.verdict == "OK"
    assert CountingOcr.calls == 1
