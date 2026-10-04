"""Tier 2: a small open-source prompt-injection classifier, run locally on CPU with onnxruntime (no text leaves the process).

The model directory holds `model.onnx`, `tokenizer.json` and `classifier.json` (model id, revision, licence, SHA-256 of
the ONNX file, index of the "injection" class). The SHA-256 is checked at load time, so a swapped or corrupted model is
refused. Long inputs are scored in overlapping 512-token windows (maximum over windows); nothing is truncated.

Fail-closed: if the model cannot be loaded or verified, the classifier reports itself unhealthy (/ready answers 503) and
every `score` raises `ClassifierUnavailable`, which the pipeline turns into a fail-closed BLOCK.

Cost bound: a 512-token window costs ~0.5-1.5 s on CPU (measured), so at most `max_windows` windows are scored: the first
half and the last half of the text. Coverage is reported (`windows_scored` < `windows_total` = partial), the cascade treats
a partially covered input as uncertain (judge, when allowed), and tier 1 (rules + NER) always scans the whole text.
"""
from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

MAX_LEN, STRIDE = 512, 64


def windows_of(ids: list[int], cls_id: int, sep_id: int) -> list[list[int]]:
    """Split token ids (no special tokens) into model inputs of at most MAX_LEN tokens, consecutive windows overlapping
    by STRIDE tokens, each wrapped as [CLS] ... [SEP]. Done by hand: the tokenizers library's `overflowing` output does
    not return every window for long inputs (measured: a 4,002-token text came back as 512 + 68 tokens)."""
    body = MAX_LEN - 2
    if len(ids) <= body:
        return [[cls_id, *ids, sep_id]]
    step = body - STRIDE
    starts = list(range(0, len(ids) - STRIDE, step))
    return [[cls_id, *ids[s:s + body], sep_id] for s in starts]


class ClassifierUnavailable(RuntimeError):
    pass


@dataclass(frozen=True)
class ClassifierScore:
    score: float
    windows_scored: int
    windows_total: int

    @property
    def partial(self) -> bool:
        return self.windows_scored < self.windows_total


class InjectionClassifier(Protocol):
    name: str
    version: str

    def healthy(self) -> bool: ...

    def score(self, text: str) -> float: ...

    def score_detail(self, text: str) -> ClassifierScore: ...


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


class OnnxInjectionClassifier:
    name = "injection_classifier"

    def __init__(self, model_dir: Path, threads: int = 1, max_windows: int = 4) -> None:
        if max_windows < 1:
            raise ValueError("max_windows must be >= 1")
        self.model_dir = model_dir
        self.max_windows = max_windows
        self.version = "unloaded"
        self.meta: dict[str, Any] = {}
        self._error: str | None = None
        self._lock = threading.Lock()
        try:
            self.meta = json.loads((model_dir / "classifier.json").read_text(encoding="utf8"))
            onnx_path = model_dir / "model.onnx"
            digest = file_sha256(onnx_path)
            if digest != self.meta["onnx_sha256"]:
                raise ClassifierUnavailable(f"model.onnx sha256 mismatch ({digest[:12]} != {self.meta['onnx_sha256'][:12]})")
            if "tokenizer_sha256" in self.meta and file_sha256(model_dir / "tokenizer.json") != self.meta["tokenizer_sha256"]:
                raise ClassifierUnavailable("tokenizer.json sha256 mismatch")
            import numpy as np
            import onnxruntime as ort  # type: ignore[import-untyped]
            from tokenizers import Tokenizer
            opts = ort.SessionOptions()
            opts.intra_op_num_threads = threads
            opts.inter_op_num_threads = 1
            self._np = np
            self._session = ort.InferenceSession(str(onnx_path), opts, providers=["CPUExecutionProvider"])
            self._inputs = {i.name for i in self._session.get_inputs()}
            self._tok = Tokenizer.from_file(str(model_dir / "tokenizer.json"))
            self._tok.no_truncation()
            self._tok.no_padding()
            cls_id, sep_id = self._tok.token_to_id("[CLS]"), self._tok.token_to_id("[SEP]")
            if cls_id is None or sep_id is None:
                raise ClassifierUnavailable("tokenizer has no [CLS]/[SEP] tokens")
            self._cls, self._sep = cls_id, sep_id
            self._index = int(self.meta["injection_index"])
            self.version = f"{self.meta['model_id']}@{self.meta['revision'][:12]}:{self.meta.get('variant', 'fp32')}"
        except Exception as exc:  # noqa: BLE001 - any load failure means "not usable", reported by healthy()
            self._error = f"{type(exc).__name__}: {exc}"

    def healthy(self) -> bool:
        return self._error is None

    @property
    def load_error(self) -> str | None:
        return self._error

    def score(self, text: str) -> float:
        return self.score_detail(text).score

    def score_detail(self, text: str) -> ClassifierScore:
        if self._error is not None:
            raise ClassifierUnavailable(self._error)
        np = self._np
        windows = windows_of(self._tok.encode(text, add_special_tokens=False).ids, self._cls, self._sep)
        total = len(windows)
        if total > self.max_windows:
            head = (self.max_windows + 1) // 2
            windows = windows[:head] + windows[total - (self.max_windows - head):]
        best = 0.0
        for window in windows:
            ids = np.array([window], dtype=np.int64)
            feed = {"input_ids": ids, "attention_mask": np.ones_like(ids)}
            if "token_type_ids" in self._inputs:
                feed["token_type_ids"] = np.zeros_like(ids)
            with self._lock:  # one session, shared: onnxruntime sessions are thread-safe, but keep scoring serial/cheap
                logits = self._session.run(None, {k: v for k, v in feed.items() if k in self._inputs})[0][0]
            e = np.exp(logits - logits.max())
            best = max(best, float(e[self._index] / e.sum()))
        return ClassifierScore(best, len(windows), total)


class StaticClassifier:
    """Test double: returns scripted scores and records what it saw."""

    name = "injection_classifier"

    def __init__(self, score: float | dict[str, float] = 0.0, version: str = "static-test", healthy: bool = True) -> None:
        self._score = score
        self.version = version
        self._healthy = healthy
        self.received: list[str] = []

    def healthy(self) -> bool:
        return self._healthy

    def score(self, text: str) -> float:
        if not self._healthy:
            raise ClassifierUnavailable("static classifier marked unhealthy")
        self.received.append(text)
        if isinstance(self._score, dict):
            return next((v for k, v in self._score.items() if k in text), 0.0)
        return self._score

    windows_total = 1  # tests can set it to simulate a long input with partial coverage
    windows_scored = 1

    def score_detail(self, text: str) -> ClassifierScore:
        return ClassifierScore(self.score(text), self.windows_scored, self.windows_total)
