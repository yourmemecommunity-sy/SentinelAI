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
