"""Named-entity recognition for PII that has no fixed format: person names and locations.

Rules cannot find "Maria Gonzalez" or "Berlin"; a statistical model can. This detector runs a small spaCy pipeline
locally (no external API, no text leaves the process) and reports:

    PERSON          -> NAME
    GPE, LOC        -> LOCATION   (countries, cities, states; regions, mountains, bodies of water)

Model choice (en_core_web_md) was made on the ai4privacy TRAIN split by measured accuracy, latency and memory; see
docs/decisions-log.md (D16) and docs/verification/11-pii-improvement-cycle.md.

Fail-closed: the model is loaded once at start-up. If it cannot be loaded, the detector reports itself unhealthy (so
/ready answers 503 and callers stop sending traffic) and every `detect` raises, which the pipeline turns into a
fail-closed BLOCK. A missing model never degrades into "no names found".

Long inputs are processed completely, in ~5,000-character windows that overlap by 200 characters (so an entity on a
window boundary is still seen whole), never truncated.
"""
from __future__ import annotations

from collections.abc import Callable, Iterator
from typing import Any

from app.detectors.base import Detector, make_detection
from app.models.types import Detection, EntityType, Severity

_LABELS: dict[str, EntityType] = {"PERSON": EntityType.NAME, "GPE": EntityType.LOCATION, "LOC": EntityType.LOCATION}
_WINDOW = 5000
_OVERLAP = 200
_CONFIDENCE = 0.8  # spaCy's NER gives no calibrated per-entity score; a fixed, below-regex confidence is honest
# Names are personal data: MEDIUM, so the baseline policy MASKs them. A city or country on its own is not (and masking
# it breaks ordinary prompts such as "what is the capital of France?"): LOW, so the baseline ALLOWs it but the detection
# is still reported and audited, and an organisation's policy can MASK or TOKENIZE LOCATION like any other type.
_SEVERITY: dict[EntityType, Severity] = {EntityType.NAME: Severity.MEDIUM, EntityType.LOCATION: Severity.LOW}


class NerUnavailable(RuntimeError):
    """The NER model is not loaded. Raised on every scan so the pipeline fails closed."""


_LOADED: dict[str, Any] = {}  # one model per process: loading takes ~2 s and ~350 MB; failures are never cached


def _load_spacy(model: str) -> Any:
    if model in _LOADED:
        return _LOADED[model]
    import spacy  # imported lazily: only engines with NER enabled need the dependency loaded

    nlp = spacy.load(model, disable=["tagger", "parser", "attribute_ruler", "lemmatizer", "senter"])
    if "ner" not in nlp.pipe_names:
        raise RuntimeError(f"model {model} has no NER component")
    nlp.max_length = _WINDOW + _OVERLAP + 100
    _LOADED[model] = nlp
    return nlp


def _windows(text: str) -> Iterator[tuple[int, str]]:
    """(offset, chunk) pairs covering the whole text; chunks end at whitespace and overlap by _OVERLAP characters."""
    n = len(text)
    start = 0
    while start < n:
        end = min(n, start + _WINDOW)
        if end < n:
            ws = text.rfind(" ", start + _WINDOW // 2, end)
            if ws > start:
                end = ws
        yield start, text[start:min(n, end + _OVERLAP)]
        start = end


# Rejection rules for statistical-model output, derived from the ai4privacy TRAIN split only: the model also tags
# identifiers, hex strings, URL/e-mail fragments and markup as PERSON/GPE, and compass words as LOC.
_NOT_A_NAME_CHARS = frozenset("0123456789@/:_{}|<>=\\#$%[]")
_COMPASS = frozenset({"north", "south", "east", "west", "northeast", "northwest", "southeast", "southwest", "central"})
# Temperature scales named after people, which the model tags as PERSON ("72 degrees Fahrenheit"). Taken from the
# self-authored benign suite, not from the independent datasets.
_UNITS = frozenset({"fahrenheit", "celsius", "kelvin"})


def _plausible(entity: EntityType, value: str) -> bool:
    """Drop entity strings that cannot be a person's name or a place."""
    stripped = value.strip()
    if len(stripped) < 2 or not any(c.isalpha() for c in stripped):
        return False
    if any(c in _NOT_A_NAME_CHARS for c in stripped):  # codes, IDs, URLs, e-mail parts, markup
        return False
    if stripped.islower():  # names and places are capitalised in text; lowercase hits were almost all noise
        return False
    if entity is EntityType.NAME and (stripped.isupper() and len(stripped) <= 3):  # "CI", "VIN", "KTU": acronyms
        return False
    if entity is EntityType.NAME and stripped.lower() in _UNITS:
        return False
    return not (entity is EntityType.LOCATION and stripped.lower() in _COMPASS)


class NerDetector(Detector):
    name = "ner"
    version = "1.0.0"

    def __init__(self, model: str = "en_core_web_md", loader: Callable[[str], Any] = _load_spacy) -> None:
        self.model = model
        self._nlp: Any = None
        self.load_error: str | None = None
        try:
            self._nlp = loader(model)
        except Exception as exc:  # noqa: BLE001 - any load failure -> unhealthy + fail closed per request
            self.load_error = f"{type(exc).__name__}"

    def healthy(self) -> bool:
        return self._nlp is not None

    def detect(self, text: str) -> list[Detection]:
        if self._nlp is None:
            raise NerUnavailable(f"NER model {self.model} is not loaded ({self.load_error})")
        chunks = list(_windows(text))
        seen: set[tuple[EntityType, int, int]] = set()
        out: list[Detection] = []
        for (offset, _chunk), doc in zip(chunks, self._nlp.pipe([c for _, c in chunks], batch_size=8), strict=True):
            for ent in doc.ents:
                entity = _LABELS.get(ent.label_)
                if entity is None or not _plausible(entity, ent.text):
                    continue
                start, end = offset + ent.start_char, offset + ent.end_char
                if (entity, start, end) in seen:
                    continue
                seen.add((entity, start, end))
                out.append(make_detection(entity, ent.text, start, end, _CONFIDENCE, _SEVERITY[entity], self.name, self.version))
        return out
