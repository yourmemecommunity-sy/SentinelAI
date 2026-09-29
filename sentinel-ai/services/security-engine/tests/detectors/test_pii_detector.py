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


# ---------------------------------------------------------------- SSN vs phone, date of birth (tuned on the TRAIN split)
def test_phone_shaped_number_after_ssn_wording_is_an_ssn_not_a_phone():
    for text in ("Social security number: 123-456-7890", "social number 123 45 6789", "SSN 123.45.6789",
                 "SIN 046 454 286", "national insurance no 1234567890"):
        got = [d.entity.value for d in det.detect(text)]
        assert "SSN" in got and "PHONE" not in got, (text, got)


def test_plain_phone_numbers_are_still_phones():
    for text in ("call me at 415-555-0132", "mobile +44 20 7946 0958"):
        got = [d.entity.value for d in det.detect(text)]
        assert "PHONE" in got and "SSN" not in got, (text, got)


def test_ssn_wording_does_not_turn_short_or_long_numbers_into_ssns():
    assert "SSN" not in [d.entity.value for d in det.detect("social security office room 1234")]
    assert "SSN" not in [d.entity.value for d in det.detect("social number 12345678901234567")]


def test_more_date_of_birth_formats_after_birth_wording():
    for text in ("Date of birth: <strong>1977-04-07T00:00:00</strong>", "born May 5th, 1966", "DOB January/88",
                 "date of birth 5th of May 1966", "birthdate: 03/14/1982"):
        assert "DATE_OF_BIRTH" in [d.entity.value for d in det.detect(text)], text


def test_dates_without_birth_wording_are_not_dates_of_birth():
    for text in ("meeting on 12/01/2024", "invoice 2024-01-05 paid", "released May 5th, 2020"):
        assert "DATE_OF_BIRTH" not in [d.entity.value for d in det.detect(text)], text


def test_the_engines_own_placeholders_are_not_context_words():
    # After masking, "[DATE_OF_BIRTH_MASKED]" / "[DRIVER_LICENSE_MASKED]" contain the context words; the verification
    # re-scan must not turn a neighbouring ordinary date or code into a "new" date of birth / licence.
    assert "DATE_OF_BIRTH" not in [d.entity.value for d in det.detect("[DATE_OF_BIRTH_MASKED], meeting on 12/01/2024")]
    assert "DRIVER_LICENSE" not in [d.entity.value for d in det.detect("[DRIVER_LICENSE_MASKED] ref AB123456")]
    # real context words still work
    assert "DATE_OF_BIRTH" in [d.entity.value for d in det.detect("date of birth 12/01/1990")]
    assert "DRIVER_LICENSE" in [d.entity.value for d in det.detect("driver license AB123456")]
