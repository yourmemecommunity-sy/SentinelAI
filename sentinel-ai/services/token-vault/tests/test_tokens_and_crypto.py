import importlib.util
import pathlib

import pytest

from app.crypto import KeyRing, digest, open_sealed, seal, session_hash
from app.errors import TokenizationRefused
from app.tokens import MAX_TOKEN_LEN, TOKENIZABLE, TOKEN_RE, is_token, is_token_prefix, make_token, normalize, require_tokenizable


# ------------------------------------------------------------------ token format
def test_token_format_roundtrip():
    assert make_token("NAME", 1) == "[TOK_NAME_1]"
    assert make_token("DATE_OF_BIRTH", 42) == "[TOK_DATE_OF_BIRTH_42]"
    m = TOKEN_RE.fullmatch("[TOK_DATE_OF_BIRTH_42]")
    assert m and m.group(1) == "DATE_OF_BIRTH" and m.group(2) == "42"


@pytest.mark.parametrize("bad", ["[TOK_name_1]", "[TOK_NAME_]", "[TOK_NAME_1", "TOK_NAME_1]", "[TOK__1]", "[TOK_NAME_1234567]", "[TOK_NAME1_1]",
                                 "[TOK_NAME_1] ", "[tok_NAME_1]", "[TOK_NAME_-1]", "[TOK_ NAME_1]", "[TOK_" + "A" * 40 + "_1]"])
def test_non_tokens_are_not_tokens(bad):
    assert not is_token(bad)


def test_make_token_rejects_bad_parameters():
    for entity, n in [("name", 1), ("NAME_", 1), ("", 1), ("NAME", 0), ("NAME", 1_000_000), ("A" * 40, 1)]:
        with pytest.raises(TokenizationRefused):
            make_token(entity, n)


def test_longest_possible_token_fits_the_documented_maximum():
    longest = make_token("A" + "B" * 30 + "C", 999_999)
    assert len(longest) == MAX_TOKEN_LEN - 0 and is_token(longest)


def test_every_prefix_of_every_token_is_held_back_and_nothing_else_is():
    token = "[TOK_DATE_OF_BIRTH_123]"
    for i in range(1, len(token)):
        assert is_token_prefix(token[:i]), token[:i]
    for tail in ["[X", "[TOKEN", "[TOK-", "[tok_", "[TOK_name", "[[", "[ TOK", "[TOK_A B", "[" + "T" * 5]:
        assert not is_token_prefix(tail), tail
    assert not is_token_prefix("[TOK_" + "A" * 60)  # too long to ever be a token: never held back


# ------------------------------------------------------------------ allow-list (cross-checked against the engine)
def _engine_types():
    path = pathlib.Path(__file__).resolve().parents[2] / "security-engine" / "app" / "models" / "types.py"
    spec = importlib.util.spec_from_file_location("engine_types", path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    import sys

    sys.modules["engine_types"] = mod
    spec.loader.exec_module(mod)
    return mod


def test_tokenizable_never_includes_credentials_secrets_cards_or_threats():
    t = _engine_types()
    forbidden = {e.value for e in t.NEVER_ALLOW_ENTITIES} | {e.value for e in t.THREAT_ENTITIES} | {"HIGH_ENTROPY_SECRET", "CONFIDENTIAL_MARKER"}
    assert forbidden, "engine sets must not be empty"
    assert TOKENIZABLE.isdisjoint(forbidden)
    for e in forbidden:
        with pytest.raises(TokenizationRefused):
            require_tokenizable(e)


def test_every_tokenizable_type_the_engine_knows_is_a_real_entity():
    t = _engine_types()
    engine = {e.value for e in t.EntityType}
    # NAME/ORGANIZATION/LOCATION are reserved for the future NER layer; everything else must exist in the engine.
    assert (TOKENIZABLE - {"NAME", "ORGANIZATION", "LOCATION"}) <= engine


def test_unknown_or_malformed_types_are_refused():
    for e in ["", "email", "SECRET", "NAME ", "TOK", "../x"]:
        with pytest.raises(TokenizationRefused):
            require_tokenizable(e)


# ------------------------------------------------------------------ normalization ('same value' only; restore keeps the first spelling)
def test_normalization_decides_sameness():
    assert normalize("NAME", "  John   Doe ") == normalize("NAME", "john doe")
    assert normalize("EMAIL", "Jane.Doe@Example.COM") == normalize("EMAIL", "jane.doe@example.com")
    assert normalize("PHONE", "+1 (415) 555-0132") == normalize("PHONE", "1 415 555 0132")
    assert normalize("PAN", "abcde1234f") == normalize("PAN", "ABCDE1234F")
    assert normalize("UPI", "Jane@Okbank") == normalize("UPI", "jane@okbank")
    assert normalize("NAME", "Ｊｏｈｎ") == normalize("NAME", "John")                      # NFKC
    assert normalize("NAME", "John Doe") != normalize("NAME", "John Do")


# ------------------------------------------------------------------ keys and sealing
K = bytes(range(32))


def keys(ring: KeyRing, org="o", session="s", kid="k1"):
    return ring.session_keys(kid, session_hash(org, session))


def test_session_keys_are_unrelated_across_sessions_and_tenants():
    ring = KeyRing({"k1": K}, "k1")
    a, b, c = keys(ring, "o", "s1"), keys(ring, "o", "s2"), keys(ring, "o2", "s1")
    assert len({a.enc, b.enc, c.enc}) == 3 and len({a.mac, b.mac, c.mac}) == 3
    assert a.enc != a.mac
    assert keys(ring, "o", "s1") == a                                                       # deterministic (and cached)


def test_digest_is_deterministic_in_a_session_and_unlinkable_outside_it():
    ring = KeyRing({"k1": K}, "k1")
    d1 = digest(keys(ring, "o", "s1"), "NAME", "john doe")
    assert d1 == digest(keys(ring, "o", "s1"), "NAME", "john doe")
    assert d1 != digest(keys(ring, "o", "s2"), "NAME", "john doe")
    assert d1 != digest(keys(ring, "o2", "s1"), "NAME", "john doe")
    assert d1 != digest(keys(KeyRing({"k1": bytes(range(1, 33))}, "k1"), "o", "s1"), "NAME", "john doe")
    assert d1 != digest(keys(ring, "o", "s1"), "EMAIL", "john doe")                         # type is part of the input
    assert len(d1) == 32 and "john" not in d1


def test_sealed_values_authenticate_and_are_bound_to_their_token():
    k = keys(KeyRing({"k1": K}, "k1"))
    blob = seal(k, "[TOK_NAME_1]", "John Doe")
    assert b"John" not in blob and open_sealed(k, "[TOK_NAME_1]", blob) == "John Doe"
    assert open_sealed(k, "[TOK_NAME_2]", blob) is None                                     # moved to another token
    assert open_sealed(keys(KeyRing({"k1": K}, "k1"), session="other"), "[TOK_NAME_1]", blob) is None   # other session
    assert seal(k, "[TOK_NAME_1]", "John Doe") != blob                                      # fresh nonce every time
    for corrupt in [b"", b"\x00", blob[:-1], blob[:-1] + bytes([blob[-1] ^ 1]), bytes([blob[0] + 5]) + blob[1:], b"\xff" * 40]:
        assert open_sealed(k, "[TOK_NAME_1]", corrupt) is None                              # never raises


def test_unicode_and_large_values_seal_correctly():
    k = keys(KeyRing({"k1": K}, "k1"))
    for v in ["José Ñandú 山田太郎 🙂", "x" * 8192]:
        assert open_sealed(k, "[TOK_NAME_1]", seal(k, "[TOK_NAME_1]", v)) == v


def test_keyring_validation():
    for bad in [lambda: KeyRing({"k1": b"short"}, "k1"), lambda: KeyRing({"k1": K}, "missing"), lambda: KeyRing({"bad id": K}, "bad id"),
                lambda: KeyRing({"k" * 9: K}, "k" * 9), lambda: KeyRing({"": K}, "")]:
        with pytest.raises(ValueError):
            bad()
    ring = KeyRing({"k1": K}, "k1")
    with pytest.raises(KeyError):
        ring.session_keys("nope", b"x" * 32)
    a, b = KeyRing.random(), KeyRing.random()
    assert keys(a, kid="dev").enc != keys(b, kid="dev").enc
