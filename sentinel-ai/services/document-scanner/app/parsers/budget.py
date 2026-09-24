from __future__ import annotations

from app.models import Blocked, Finding


class Budget:
    """Caps extracted text. Exceeding it BLOCKS the file: content beyond the cap would otherwise go unscanned."""

    def __init__(self, max_chars: int) -> None:
        self.max_chars = max_chars
        self.used = 0

    def add(self, s: str) -> str:
        self.used += len(s) + 1
        if self.used > self.max_chars:
            raise Blocked("text_too_large", [Finding(type="text_too_large", severity="MEDIUM",
                                                     detail=f"extracted text exceeds {self.max_chars} characters")])
        return s
