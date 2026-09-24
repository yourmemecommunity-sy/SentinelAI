import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))  # so tests can `import samples`

from app.config.settings import Settings  # noqa: E402
from app.malware.scanners import EicarScanner  # noqa: E402
from app.models import Blocked  # noqa: E402
from app.ocr.engine import UnavailableOcr  # noqa: E402
from app.pipelines.extract_pipeline import ExtractPipeline  # noqa: E402


class FakeOcr:
    name = "fake"

    def __init__(self, text: str = "") -> None:
        self.text = text
        self.calls = 0

    def available(self) -> bool:
        return True

    def extract(self, data: bytes, mime: str) -> str:
        self.calls += 1
        return self.text


def make_pipeline(**overrides) -> ExtractPipeline:
    ocr = overrides.pop("ocr", FakeOcr("invoice total 42"))
    malware = overrides.pop("malware", EicarScanner())
    settings = Settings(isolation=False, **overrides)     # in-process for speed; isolation has its own tests
    return ExtractPipeline(settings, malware, ocr)


@pytest.fixture
def pipe() -> ExtractPipeline:
    return make_pipeline()


def assert_blocked(result, reason: str | None = None):
    assert result.verdict == "BLOCK", result
    assert result.text == "" and result.text_chars == 0, "a BLOCKED file must never return text"
    if reason:
        assert result.block_reason is not None and result.block_reason.startswith(reason), result.block_reason


__all__ = ["FakeOcr", "UnavailableOcr", "make_pipeline", "assert_blocked", "Blocked"]
