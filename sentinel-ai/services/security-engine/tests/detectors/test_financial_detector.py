from app.detectors.financial import build_financial_detector
from conftest import valid_card

det = build_financial_detector()


def entities(text: str) -> set[str]:
    return {d.entity.value for d in det.detect(text)}


def test_credit_card_luhn_valid_variants():
    card = valid_card()
    assert "CREDIT_CARD" in entities(f"pay with {card}")
    grouped = " ".join(card[i:i + 4] for i in range(0, 16, 4))
    assert "CREDIT_CARD" in entities(f"pay with {grouped}")
    assert "CREDIT_CARD" in entities("card 4111-1111-1111-1111")


def test_credit_card_rejects_non_luhn_and_repeated_digits():
    assert "CREDIT_CARD" not in entities("order 4111111111111112")
    assert "CREDIT_CARD" not in entities("id 0000000000000000")


def test_bank_account_requires_context():
    assert "BANK_ACCOUNT" in entities("account number 123456789012")
    assert "BANK_ACCOUNT" not in entities("tracking 123456789012")


def test_iban_checksum():
    assert "BANK_ACCOUNT" in entities("iban GB82 WEST 1234 5698 7654 32")
    assert "BANK_ACCOUNT" not in entities("code GB00 WEST 1234 5698 7654 32")


def test_upi_and_ifsc():
    assert "UPI" in entities("pay to rahul.k@okaxis")
    assert "IFSC" in entities("IFSC HDFC0001234")
    assert "EMAIL" not in entities("pay to rahul.k@okaxis")


# ---------------------------------------------------------------- IMEI vs card (independent-evaluation regression)
from app.utils.checksums import luhn_check_digit  # noqa: E402


def luhn_number(payload: str) -> str:
    return payload + luhn_check_digit(payload)


# Synthetic IMEIs: 8-digit type allocation code + 6-digit serial + Luhn check digit = 15 digits (like real IMEIs,
# which start with reporting-body codes such as 01, 35, 86, 99). All are Luhn-valid, exactly like card numbers.
SYNTHETIC_IMEIS = [luhn_number(p) for p in ("35209900176148", "86891203987654", "01326300123456", "99000123456789",
                                           "35693803564380", "86730301234567")]


def test_imeis_are_luhn_valid_so_luhn_alone_cannot_tell_them_from_cards():
    from app.utils.checksums import luhn_valid
    assert all(len(i) == 15 and luhn_valid(i) for i in SYNTHETIC_IMEIS)


def test_imei_is_not_reported_as_a_credit_card_with_or_without_context():
    for imei in SYNTHETIC_IMEIS:
        for text in (f"IMEI: {imei}", f"device {imei} was registered", f"The phone's IMEI number is {imei}.", imei):
            assert "CREDIT_CARD" not in entities(text), text


def test_a_card_number_labelled_as_an_imei_is_not_reported_as_a_card():
    # a Visa-shaped, Luhn-valid 16-digit value right after "IMEI" is treated as the device id the text says it is
    assert "CREDIT_CARD" not in entities(f"IMEI {valid_card()}")


def test_every_card_network_is_still_detected_at_its_issued_lengths():
    cards = {
        "visa-16": luhn_number("411111111111111"), "visa-13": luhn_number("422222222222"),
        "mastercard-51": luhn_number("555555555555444"), "mastercard-2series": luhn_number("222100000000000"),
        "amex-15": luhn_number("37828224631000"), "diners-14": luhn_number("3056930902590"),
        "jcb-16": luhn_number("353011133330000"), "discover-16": luhn_number("601111111111111"),
        "unionpay-16": luhn_number("620000000000000"), "maestro-19": luhn_number("675941100000000000"),
        "rupay-16": luhn_number("608000000000000"),
    }
    for name, card in cards.items():
        assert "CREDIT_CARD" in entities(f"pay with card {card}"), name


def test_luhn_valid_numbers_outside_any_network_length_are_rejected():
    assert "CREDIT_CARD" not in entities(f"ref {luhn_number('35000000000001')}")      # 15 digits, JCB prefix: JCB is 16-19
    assert "CREDIT_CARD" not in entities(f"ref {luhn_number('4111111111111')}")       # 14 digits Visa: not an issued length
    assert "CREDIT_CARD" not in entities(f"ref {luhn_number('86000000000000000')}")   # 18 digits starting 86: no network
