import random
import string

from app.detectors.credentials import build_credential_detector
from app.detectors.secrets import build_secret_detectors
from conftest import (
    fake_aws_key, fake_github_token, fake_google_key, fake_jwt, fake_pem, fake_stripe_key,
)

_dets = [*build_secret_detectors(), build_credential_detector()]


def random_token(n: int, alphabet: str, seed: int) -> str:
    """A random-looking value generated at test time (seeded, so reproducible), never stored as a literal."""
    rng = random.Random(seed)
    return "".join(rng.choice(alphabet) for _ in range(n))


def entities(text: str) -> set[str]:
    return {d.entity.value for det in _dets for d in det.detect(text)}


def test_aws_access_key():
    assert "AWS_CREDENTIAL" in entities(f"key={fake_aws_key()}")


def test_aws_secret_needs_context_and_entropy():
    secret = random_token(40, string.ascii_letters + string.digits + "/+", seed=40)  # AWS-secret shaped
    assert len(secret) == 40
    assert "AWS_CREDENTIAL" in entities(f"aws_secret_access_key = {secret}")
    assert "AWS_CREDENTIAL" not in entities(f"blob {secret}")


def test_github_google_stripe_tokens():
    assert "GITHUB_TOKEN" in entities(f"token {fake_github_token()}")
    assert "GOOGLE_CREDENTIAL" in entities(f"key {fake_google_key()}")
    assert "API_KEY" in entities(f"stripe {fake_stripe_key()}")


def test_jwt():
    assert "JWT" in entities(f"Authorization {fake_jwt()}")


def test_private_key_block_covers_whole_body():
    pem = fake_pem()
    text = f"here:\n{pem}\nthanks"
    dets = [d for det in _dets for d in det.detect(text) if d.entity.value == "PRIVATE_KEY"]
    assert dets
    covered = max(dets, key=lambda d: d.location.end - d.location.start)
    assert covered.location.start == text.index("-----BEGIN")
    assert covered.location.end == text.index("thanks") - 1


def test_truncated_private_key_consumes_to_end():
    pem = fake_pem().split("-----END")[0]
    text = f"key:\n{pem}"
    (d,) = [d for det in _dets for d in det.detect(text) if d.entity.value == "PRIVATE_KEY"]
    assert d.location.end == len(text)


def test_passwords():
    assert "PASSWORD" in entities("my password is Tr0ub4dor&3")
    assert "PASSWORD" in entities("DB_PASSWORD=s3cretValue!")
    assert "PASSWORD" not in entities("password: ********")
    assert "PASSWORD" not in entities("password: <your-password>")
    assert "PASSWORD" not in entities("password: ${DB_PASSWORD}")


def test_connection_strings_and_bearer():
    assert "CONNECTION_STRING" in entities("postgresql://app:hunter2pw@db.internal:5432/prod")
    assert "CONNECTION_STRING" not in entities("postgresql://db.internal:5432/prod")
    assert "OAUTH_TOKEN" in entities("Authorization: Bearer abcdEFGH1234567890abcdEFGH")


def test_entropy_detector_needs_keyword_or_long_random_token():
    assert "HIGH_ENTROPY_SECRET" in entities(f"internal_token: {random_token(31, string.ascii_letters + string.digits, seed=31)}")
    assert "HIGH_ENTROPY_SECRET" not in entities("commit 3f786850e387550fdab836ed7e6dc881de23001b")
    assert "HIGH_ENTROPY_SECRET" not in entities("the quick brown fox jumps over the lazy dog again")


def test_detections_never_contain_secret_material():
    text = f"key={fake_aws_key()} pw: hunter2pw!"
    for det in _dets:
        for d in det.detect(text):
            dumped = d.model_dump_json()
            assert fake_aws_key() not in dumped and "hunter2pw" not in dumped
