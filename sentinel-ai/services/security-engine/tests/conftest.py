"""Test fixtures. Secret-shaped values are assembled at runtime so no such literal exists in source
(keeps the repo-wide secret scanner clean, and none of these is a real credential)."""
import base64
import json

import pytest

from app.detectors.registry import default_registry
from app.pipelines import ScanPipeline
from app.utils.checksums import luhn_check_digit, verhoeff_check_digit


def fake_aws_key() -> str:
    return "AK" + "IA" + "ABCDEFGHIJKLMNOP"


def fake_github_token() -> str:
    return "gh" + "p_" + "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7bC0eF3hJ6"


def fake_google_key() -> str:
    return "AI" + "za" + "SyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q"


def fake_jwt() -> str:
    def enc(o: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(o).encode()).decode().rstrip("=")
    return f"{enc({'alg': 'HS256', 'typ': 'JWT'})}.{enc({'sub': 'synthetic-user', 'iat': 1})}.c2lnbmF0dXJlLXN5bnRoZXRpYw"


def fake_pem() -> str:
    body = "\n".join(["QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo"] * 4)
    return "-----BEGIN " + "RSA PRIVATE KEY-----\n" + body + "\n-----END " + "RSA PRIVATE KEY-----"


def fake_stripe_key() -> str:
    return "sk" + "_live_" + "aBcDeFgHiJkLmNoPqRsTuVwX"


def valid_aadhaar_like() -> str:
    payload = "23456789012"
    return payload + verhoeff_check_digit(payload)


def valid_card(prefix: str = "411111111111111") -> str:
    return prefix + luhn_check_digit(prefix)


@pytest.fixture(scope="session")
def pipeline() -> ScanPipeline:
    return ScanPipeline(default_registry())
