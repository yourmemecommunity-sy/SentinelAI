"""Hard spending cap for Anthropic API calls (the Tier-3 judge and the red-team generator).

Every call is priced BEFORE it is sent (input estimated from characters, output at `max_tokens`, i.e. the worst case)
and refused if the running total could exceed the cap; after the call the estimate is replaced by the actual usage the
API reported. The ledger can be shared by several processes (engine workers, scripts) through a JSON file guarded by an
exclusive lock, so the cap holds across processes; without a file it is per-process.

Prices are USD per million tokens from Anthropic's published price list (cached 2026-09-25). A model that is not in the
table cannot be priced, so it is refused: an unknown cost must not slip past a hard cap.
"""
from __future__ import annotations

import json
import os
import threading
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

# (input, output) USD per 1M tokens.
PRICES_PER_MTOK: dict[str, tuple[float, float]] = {
    "claude-haiku-4-5": (1.00, 5.00),
    "claude-sonnet-5-5": (2.00, 10.00),
    "claude-opus-5-5": (4.00, 20.00),
}
CHARS_PER_TOKEN_ESTIMATE = 3.0  # deliberately pessimistic (English averages ~4); the estimate is only a pre-call bound


class BudgetExceeded(RuntimeError):
    """The next call could take the run past its cap. No call is made."""


def estimate_tokens(chars: int) -> int:
    return int(chars / CHARS_PER_TOKEN_ESTIMATE) + 1


def cost_usd(model: str, input_tokens: int, output_tokens: int) -> float:
    if model not in PRICES_PER_MTOK:
        raise BudgetExceeded(f"no price known for model '{model}'; refusing to call it under a hard cap")
    price_in, price_out = PRICES_PER_MTOK[model]
    return (input_tokens * price_in + output_tokens * price_out) / 1_000_000


@dataclass
class Usage:
    calls: int = 0
    refused: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    spent_usd: float = 0.0
    by_purpose: dict[str, dict[str, float]] = field(default_factory=dict)


class BudgetLedger:
    def __init__(self, cap_usd: float, path: Path | None = None) -> None:
        if cap_usd < 0:
            raise ValueError("budget cap must be >= 0")
        self.cap_usd = cap_usd
        self.path = path
        self._lock = threading.Lock()
        self._usage = Usage()

    @classmethod
    def from_env(cls) -> "BudgetLedger":
        path = os.environ.get("ANTHROPIC_USAGE_LEDGER")
        return cls(float(os.environ.get("ANTHROPIC_BUDGET_USD", "5")), Path(path) if path else None)

    # -- shared state -------------------------------------------------------------------------------------------------
    @contextmanager
    def _state(self) -> Iterator[Usage]:
        with self._lock:
            if self.path is None:
                yield self._usage
                return
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.path, "a+", encoding="utf8") as fh:
                _lock_file(fh)
                try:
                    fh.seek(0)
                    raw = fh.read()
                    data = json.loads(raw) if raw.strip() else {}
                    usage = Usage(**data) if data else Usage()
                    yield usage
                    fh.seek(0)
                    fh.truncate()
                    fh.write(json.dumps(usage.__dict__))
                    fh.flush()
                finally:
                    _unlock_file(fh)

    def reserve(self, model: str, input_chars: int, max_output_tokens: int) -> float:
        """Raise BudgetExceeded unless the worst case of this call still fits. Returns the reserved amount."""
        worst = cost_usd(model, estimate_tokens(input_chars), max_output_tokens)
        with self._state() as u:
            if u.spent_usd + worst > self.cap_usd:
                u.refused += 1
                raise BudgetExceeded(f"budget cap ${self.cap_usd:.2f} reached (spent ${u.spent_usd:.4f}, "
                                     f"next call up to ${worst:.4f})")
            u.spent_usd += worst
        return worst

    def settle(self, reserved: float, model: str, input_tokens: int, output_tokens: int, purpose: str) -> float:
        """Replace a reservation by the real cost reported by the API (or keep the reservation if the call failed)."""
        actual = cost_usd(model, input_tokens, output_tokens)
        with self._state() as u:
            u.spent_usd += actual - reserved
            u.calls += 1
            u.input_tokens += input_tokens
            u.output_tokens += output_tokens
            p = u.by_purpose.setdefault(purpose, {"calls": 0, "input_tokens": 0, "output_tokens": 0, "usd": 0.0})
            p["calls"] += 1
            p["input_tokens"] += input_tokens
            p["output_tokens"] += output_tokens
            p["usd"] = round(p["usd"] + actual, 6)
        return actual

    def snapshot(self) -> dict[str, object]:
        with self._state() as u:
            return {"cap_usd": self.cap_usd, "spent_usd": round(u.spent_usd, 6), "calls": u.calls, "refused": u.refused,
                    "input_tokens": u.input_tokens, "output_tokens": u.output_tokens, "by_purpose": u.by_purpose}


def _lock_file(fh: object) -> None:
    try:
        import fcntl
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX)  # type: ignore[attr-defined]
    except ImportError:  # Windows (development/tests): the in-process lock above still serialises this process
        pass


def _unlock_file(fh: object) -> None:
    try:
        import fcntl
        fcntl.flock(fh.fileno(), fcntl.LOCK_UN)  # type: ignore[attr-defined]
    except ImportError:
        pass
