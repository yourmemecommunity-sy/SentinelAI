"""NER layer: real-model behaviour, and the fail-closed / verification guarantees with a controllable stub model.

All names and places here are synthetic examples.
"""
from __future__ import annotations

from dataclasses import dataclass

import pytest
from fastapi.testclient import TestClient

from app.config.settings import Settings
from app.detectors.ner import NerDetector
from app.detectors.registry import DetectorRegistry, default_registry
from app.main import create_app
from app.models import ScanRequest
from app.models.types import Action
from app.policies import Policy
from app.pipelines import ScanPipeline

real = NerDetector()


def found(text: str) -> set[tuple[str, str]]:
    return {(d.entity.value, text[d.location.start:d.location.end]) for d in real.detect(text)}


# ---------------------------------------------------------------- real model (en_core_web_md)
def test_real_model_is_loaded_and_healthy():
    assert real.healthy(), real.load_error


def test_person_names_and_places_are_detected():
    got = found("Please forward the contract to Maria Gonzalez in Berlin before Friday.")
    assert ("NAME", "Maria Gonzalez") in got
    assert ("LOCATION", "Berlin") in got


def test_identifiers_urls_and_lowercase_noise_are_not_reported_as_names():
    got = found("Ticket AMOUNT_1 for user_42 at https://example.com/x, mac 0a:1b:2c, ref POLICYNUM_13, and west wing")
    assert not {e for e, _ in got} & {"NAME"}, got


def test_compass_words_are_not_locations():
    assert ("LOCATION", "Southeast") not in found("Sales in the Southeast grew while the West stayed flat.")


def test_long_input_is_covered_end_to_end_across_window_boundaries():
    filler = "The quarterly budget review covered routine items only. " * 400   # ~22,800 chars, several NER windows
    text = filler + "Please call Maria Gonzalez about it." + filler + "She lives in Berlin now."
    got = found(text)
    assert ("NAME", "Maria Gonzalez") in got and ("LOCATION", "Berlin") in got


def test_offsets_point_at_the_entity_in_the_original_text():
    text = "x " * 3000 + "Contact Maria Gonzalez today."
    names = [d for d in real.detect(text) if d.entity.value == "NAME"]
    assert names and text[names[0].location.start:names[0].location.end] == "Maria Gonzalez"


def test_names_are_masked_and_locations_reported_but_allowed_by_the_baseline(pipeline):
    r = pipeline.scan(ScanRequest(text="Ask Maria Gonzalez from Berlin to email jane.doe@example.com.", organization_id="t"))
    assert r.decision is Action.MASK and not r.failed_closed
    assert r.sanitized_text is not None
    assert "Maria Gonzalez" not in r.sanitized_text and "[NAME_MASKED]" in r.sanitized_text
    # a place on its own is not personal data: detected and audited, but the baseline lets it through
    assert "LOCATION" in {d.entity.value for d in r.detections} and "Berlin" in r.sanitized_text


def test_an_organisation_policy_can_mask_locations(pipeline):
    policy = Policy.model_validate({"policy_id": "mask-places", "rules": [{"entity": "LOCATION", "action": "MASK"}]})
    r = pipeline.scan(ScanRequest(text="The offsite is in Lisbon in November.", organization_id="t", policy=policy))
    assert r.decision is Action.MASK and r.sanitized_text == "The offsite is in [LOCATION_MASKED] in November."


def test_ordinary_prompts_with_places_and_units_are_not_blocked_or_masked(pipeline):
    for text in ("What is the capital of France?", "Convert 72 degrees Fahrenheit to Celsius.",
                 "The build takes about 4 minutes on the CI runner."):
        r = pipeline.scan(ScanRequest(text=text, organization_id="t"))
        assert r.decision is Action.ALLOW and r.sanitized_text == text, (text, r.decision)


# ---------------------------------------------------------------- fail closed when the model is unavailable
def _raise(_model: str) -> object:
    raise OSError("model files missing")


def broken_pipeline() -> ScanPipeline:
    reg = default_registry(Settings(ner_enabled=False))
    reg.register(NerDetector("en_core_web_md", loader=_raise))
    return ScanPipeline(reg)


def test_an_unloadable_model_makes_the_detector_unhealthy_and_the_engine_not_ready():
    det = NerDetector("en_core_web_md", loader=_raise)
    assert not det.healthy() and det.load_error == "OSError"
    p = broken_pipeline()
    assert not p.is_ready()


def test_every_scan_fails_closed_without_the_model_even_for_clean_text():
    p = broken_pipeline()
    r = p.scan(ScanRequest(text="What is the capital of France?", organization_id="t"))
    assert r.failed_closed and r.decision is Action.BLOCK and r.sanitized_text is None
    assert r.fail_closed_reason == "detector_unavailable:ner"


def test_ready_endpoint_answers_503_without_the_model():
    client = TestClient(create_app(Settings(), pipeline=broken_pipeline()))
    assert client.get("/ready").status_code == 503


@dataclass
class _Ent:
    text: str
    label_: str
    start_char: int
    end_char: int


class _StubNlp:
    """Tags every occurrence of the given words, or nothing at all."""

    def __init__(self, words: dict[str, str]) -> None:
        self.words = words

    def pipe(self, texts, batch_size=8):
        for t in texts:
            ents = []
            for w, label in self.words.items():
                i = t.find(w)
                while i != -1:
                    ents.append(_Ent(w, label, i, i + len(w)))
                    i = t.find(w, i + 1)
            yield type("Doc", (), {"ents": ents})()


def stub_pipeline(words: dict[str, str]) -> ScanPipeline:
    reg = default_registry(Settings(ner_enabled=False))
    reg.register(NerDetector("stub", loader=lambda _m: _StubNlp(words)))
    return ScanPipeline(reg)


def test_a_model_that_loads_but_finds_nothing_fails_the_readiness_canary():
    assert not stub_pipeline({}).self_test()
    assert stub_pipeline({"Maria Gonzalez": "PERSON"}).self_test()


def test_production_refuses_to_start_with_ner_switched_off(monkeypatch):
    monkeypatch.setenv("SENTINEL_ENV", "production")
    monkeypatch.setenv("SECURITY_ENGINE_TOKEN", "t" * 32)
    monkeypatch.setenv("SENTINEL_NER", "off")
    with pytest.raises(RuntimeError, match="SENTINEL_NER=off"):
        Settings.from_env()


# ---------------------------------------------------------------- verification of NER sanitization (value-based)
class _FirstOnlyNlp(_StubNlp):
    """Tags only the FIRST occurrence of each word: a model that misses a repeated name."""

    def pipe(self, texts, batch_size=8):
        for t in texts:
            ents = [_Ent(w, lab, t.find(w), t.find(w) + len(w)) for w, lab in self.words.items() if t.find(w) != -1]
            yield type("Doc", (), {"ents": ents})()


def test_a_sanitized_name_that_survives_elsewhere_in_the_output_fails_closed():
    reg = default_registry(Settings(ner_enabled=False))
    reg.register(NerDetector("stub", loader=lambda _m: _FirstOnlyNlp({"Maria Gonzalez": "PERSON"})))
    r = ScanPipeline(reg).scan(ScanRequest(text="Maria Gonzalez called. Later Maria Gonzalez called again.", organization_id="t"))
    assert r.failed_closed and r.fail_closed_reason == "sanitization_verification_failed"


def test_a_new_name_tagged_only_in_the_altered_text_does_not_block():
    # The second pass tags a DIFFERENT word ("Later") that the first pass did not: not a surviving sanitized value.
    class Shifty(_StubNlp):
        def pipe(self, texts, batch_size=8):
            for t in texts:
                if "[NAME_MASKED]" in t:
                    i = t.find("Later")
                    yield type("Doc", (), {"ents": [_Ent("Later", "PERSON", i, i + 5)]})()
                else:
                    i = t.find("Maria Gonzalez")
                    yield type("Doc", (), {"ents": [_Ent("Maria Gonzalez", "PERSON", i, i + 14)]})()

    reg = default_registry(Settings(ner_enabled=False))
    reg.register(NerDetector("stub", loader=lambda _m: Shifty({})))
    r = ScanPipeline(reg).scan(ScanRequest(text="Maria Gonzalez called. Later we spoke.", organization_id="t"))
    assert not r.failed_closed and r.decision is Action.MASK
    assert r.sanitized_text == "[NAME_MASKED] called. Later we spoke."


def test_rule_based_types_keep_the_strict_any_residual_verification():
    # unchanged behaviour for deterministic detectors: registry without NER still verifies by type
    p = ScanPipeline(DetectorRegistry(list(default_registry(Settings(ner_enabled=False)).detectors)))
    r = p.scan(ScanRequest(text="mail jane.doe@example.com", organization_id="t"))
    assert r.decision is Action.MASK and not r.failed_closed


def test_a_large_input_completes_within_the_length_aware_budget(pipeline):
    # ~100k characters: NER alone needs ~2 s here, beyond the old flat 1.5 s budget; the budget now grows with length
    text = ("The quarterly budget review covered routine items. " * 2000) + "Contact Maria Gonzalez."
    r = pipeline.scan(ScanRequest(text=text, organization_id="t"))
    assert not r.failed_closed, r.fail_closed_reason
    assert "NAME" in {d.entity.value for d in r.detections}
