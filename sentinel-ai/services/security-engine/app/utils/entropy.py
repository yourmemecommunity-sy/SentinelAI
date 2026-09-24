from __future__ import annotations

import math
from collections import Counter


def shannon_entropy(s: str) -> float:
    """Bits per character."""
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())
