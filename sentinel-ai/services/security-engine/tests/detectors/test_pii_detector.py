from app.detectors.pii import build_pii_detector
from conftest import valid_aadhaar_like

det = build_pii_detector()


def entities(text: str) -> set[str]:
    return {d.entity.value for d in det.detect(text)}


def test_email_with_exact_offsets():
    text = "Contact user@example.com today"
    (d,) = [d for d in det.detect(text) if d.entity.value == "EMAIL"]
    assert text[d.location.start:d.location.end] == "user@example.com"
    assert d.value_digest and "user@example.com" not in d.model_dump_json()


def test_phone_formats():
    assert "PHONE" in entities("call +1 415 555 0132 now")
    assert "PHONE" in entities("call (415) 555-0132")
    assert "PHONE" in entities("mobile 9876543210")


def test_pan_valid_shape_only():
    assert "PAN" in entities("PAN is ABCPE1234F")
    assert "PAN" not in entities("code ABCDE12345")


def test_aadhaar_requires_checksum_or_context():
    good = valid_aadhaar_like()
    spaced = f"{good[:4]} {good[4:8]} {good[8:]}"
    assert "AADHAAR" in entities(f"id {spaced}")
    bad = "2345 6789 0123"  # fails Verhoeff
    assert "AADHAAR" not in entities(f"order {bad}")
    assert "AADHAAR" in entities(f"aadhaar number {bad}")


def test_ssn_and_invalid_ssn():
    assert "SSN" in entities("ssn 123-45-6789")
    assert "SSN" not in entities("ref 000-12-3456")
    assert "SSN" not in entities("ref 666-12-3456")


def test_passport_needs_context():
    assert "PASSPORT" in entities("passport no K1234567")
    assert "PASSPORT" not in entities("part number K1234567")


def test_dob_needs_context():
    assert "DATE_OF_BIRTH" in entities("DOB: 14/03/1990")
    assert "DATE_OF_BIRTH" not in entities("meeting on 14/03/2026")


def test_driver_license_needs_context():
    assert "DRIVER_LICENSE" in entities("driver's license D1234567")
    assert "DRIVER_LICENSE" not in entities("item D1234567")


def test_benign_text_is_clean():
    assert entities("The quarterly report shows revenue grew 12% year over year.") == set()
