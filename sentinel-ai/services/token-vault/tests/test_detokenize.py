import copy
import random

import pytest

from app.detokenize import MAX_DEPTH, MAX_STREAM_LOOKUPS, StreamState, detokenize_json, detokenize_stream
from app.errors import VaultUnavailable
from app.tokens import MAX_TOKEN_LEN

VALUES = {"[TOK_NAME_1]": "John Doe", "[TOK_EMAIL_1]": "john.doe@example.com", "[TOK_PHONE_1]": "+1 415 555 0132", "[TOK_NAME_2]": "Ana [TOK_NAME_1] Ruiz"}


class StubVault:
    """Answers from a dict and counts calls, so the state machine is tested without Redis."""

    def __init__(self, values=None, fail=False):
        self.values = VALUES if values is None else values
        self.calls: list[list[str]] = []
        self.fail = fail

    async def resolve(self, ref, tokens):
        toks = list(tokens)
        self.calls.append(toks)
        if self.fail:
            raise VaultUnavailable("down")
        return {t: self.values[t] for t in toks if t in self.values}


def expected(text: str, values=None) -> str:
    """Single-pass replacement: hydrated values are NOT scanned again (a value that looks like a token stays as it is)."""

    from app.tokens import TOKEN_RE

    vals = VALUES if values is None else values
    return TOKEN_RE.sub(lambda m: vals.get(m.group(0), m.group(0)), text)


async def run_stream(chunks, vault=None, state=None):
    v = vault or StubVault()
    st = state or StreamState()
    out = [await detokenize_stream(c, "s", vault=v, org_id="o", state=st) for c in chunks]
    out.append(await detokenize_stream("", "s", vault=v, org_id="o", state=st, final=True))
    return "".join(out), st, v


TEXT = ("Hello [TOK_NAME_1], mail [TOK_EMAIL_1] or call [TOK_PHONE_1]. Unknown [TOK_NAME_9] stays, [not a token] stays, [TOK_x] and [TOK_NAME_]"
        " stay; [TOK_NAME_2] keeps its inner text. Done [TOK_NAME_1]")


# ------------------------------------------------------------------ streaming: every chunk boundary
async def test_whole_text_in_one_chunk():
    out, st, _ = await run_stream([TEXT])
    assert out == expected(TEXT) and st.carry == ""
    assert "John Doe" in out and "[TOK_NAME_9]" in out and "[not a token]" in out


async def test_every_possible_two_way_split_gives_the_same_result():
    want = expected(TEXT)
    for i in range(len(TEXT) + 1):
        out, _, _ = await run_stream([TEXT[:i], TEXT[i:]])
        assert out == want, i


async def test_one_character_at_a_time():
    out, st, _ = await run_stream(list(TEXT))
    assert out == expected(TEXT) and st.carry == ""


async def test_random_multiway_splits_and_the_carry_never_exceeds_a_partial_token():
    rng = random.Random(1234)
    want = expected(TEXT)
    for _ in range(600):
        cuts = sorted(rng.sample(range(1, len(TEXT)), rng.randint(1, 12)))
        chunks = [TEXT[a:b] for a, b in zip([0] + cuts, cuts + [len(TEXT)])]
        st = StreamState()
        got = []
        v = StubVault()
        for c in chunks:
            got.append(await detokenize_stream(c, "s", vault=v, org_id="o", state=st))
            assert len(st.carry) < MAX_TOKEN_LEN
        got.append(await detokenize_stream("", "s", vault=v, org_id="o", state=st, final=True))
        assert "".join(got) == want


async def test_text_is_released_immediately_only_the_partial_token_is_held():
    st = StreamState()
    v = StubVault()
    assert await detokenize_stream("Hello wor", "s", vault=v, org_id="o", state=st) == "Hello wor"        # nothing held
    assert await detokenize_stream("ld [TOK_NA", "s", vault=v, org_id="o", state=st) == "ld "             # only the partial token
    assert st.carry == "[TOK_NA"
    assert await detokenize_stream("ME_1] and", "s", vault=v, org_id="o", state=st) == "John Doe and"
    assert st.carry == ""


async def test_a_bracket_that_cannot_be_a_token_is_not_held_back():
    st = StreamState()
    for tail in ["see [1]", "list [x", "array[0", "[TOKEN", "a [ b"]:
        st.carry = ""
        out = await detokenize_stream(tail, "s", vault=StubVault(), org_id="o", state=st)
        assert out == tail and st.carry == "", tail


async def test_an_unfinished_token_at_the_end_is_flushed_literally():
    out, _, _ = await run_stream(["value [TOK_NAME_"])
    assert out == "value [TOK_NAME_"


async def test_hydrated_values_are_not_rescanned():
    out, _, _ = await run_stream(["[TOK_NAME_2] and [TOK_NAME_", "1]"])
    assert out == "Ana [TOK_NAME_1] Ruiz and John Doe"          # NAME_2's value contains a token; it must stay literal


async def test_repeated_tokens_are_looked_up_once_per_stream():
    _, _, v = await run_stream(["[TOK_NAME_1] ", "[TOK_NAME_1] [TOK_EMAIL_1] ", "[TOK_NAME_1] [TOK_EMAIL_1]"])
    assert sum(len(c) for c in v.calls) == 2 and len(v.calls) == 2


async def test_unresolvable_tokens_are_negatively_cached():
    _, _, v = await run_stream(["[TOK_NAME_9] ", "[TOK_NAME_9] ", "[TOK_NAME_9]"])
    assert len(v.calls) == 1


async def test_a_model_guessing_many_tokens_cannot_amplify_into_the_vault():
    guesses = " ".join(f"[TOK_NAME_{i}]" for i in range(1, MAX_STREAM_LOOKUPS + 200))
    out, st, v = await run_stream([guesses])
    assert sum(len(c) for c in v.calls) == MAX_STREAM_LOOKUPS and st.lookups == MAX_STREAM_LOOKUPS
    assert out.count("[TOK_NAME_") >= 200                        # beyond the cap they simply stay as tokens


async def test_stateless_call_handles_whole_messages():
    assert await detokenize_stream("Hi [TOK_NAME_1]!", "s", vault=StubVault(), org_id="o") == "Hi John Doe!"


async def test_empty_and_plain_chunks():
    out, _, v = await run_stream(["", "plain ", "", "text"])
    assert out == "plain text" and v.calls == []


async def test_unicode_and_emoji_survive_chunking():
    text = "Grüße 🙂 [TOK_NAME_1] — 山田 [TOK_EMAIL_1] ✓"
    for i in range(len(text) + 1):
        out, _, _ = await run_stream([text[:i], text[i:]])
        assert out == expected(text), i


# ------------------------------------------------------------------ streaming: vault failure
async def test_vault_outage_degrades_to_unhydrated_tokens_and_recovers():
    v = StubVault(fail=True)
    st = StreamState()
    a = await detokenize_stream("Hi [TOK_NAME_1] ", "s", vault=v, org_id="o", state=st)
    assert a == "Hi [TOK_NAME_1] " and st.degraded            # safe direction: no plaintext, no exception
    v.fail = False
    b = await detokenize_stream("and [TOK_NAME_1]", "s", vault=v, org_id="o", state=st)
    assert b == "and John Doe"                                # failures are not cached: a later chunk hydrates once the vault is back


async def test_raise_mode_leaves_the_state_untouched():
    v = StubVault(fail=True)
    st = StreamState()
    await detokenize_stream("start [TOK_NA", "s", vault=StubVault(), org_id="o", state=st)
    carry_before = st.carry
    with pytest.raises(VaultUnavailable):
        await detokenize_stream("ME_1] end", "s", vault=v, org_id="o", state=st, on_unavailable="raise")
    assert st.carry == carry_before


# ------------------------------------------------------------------ JSON
async def dj(payload, vault=None, **kw):
    return await detokenize_json(payload, "s", vault=vault or StubVault(), org_id="o", **kw)


async def test_json_hydrates_nested_structures_with_one_batched_lookup():
    v = StubVault()
    payload = {"to": "[TOK_EMAIL_1]", "n": 3, "ok": True, "none": None, "f": 1.5,
               "body": {"lines": ["Dear [TOK_NAME_1],", "call [TOK_PHONE_1] or [TOK_PHONE_1]", ["deep [TOK_NAME_1]", {"x": "[TOK_EMAIL_1]"}]]}}
    out = await dj(payload, v)
    assert out == {"to": "john.doe@example.com", "n": 3, "ok": True, "none": None, "f": 1.5,
                   "body": {"lines": ["Dear John Doe,", "call +1 415 555 0132 or +1 415 555 0132", ["deep John Doe", {"x": "john.doe@example.com"}]]}}
    assert len(v.calls) == 1 and sorted(v.calls[0]) == ["[TOK_EMAIL_1]", "[TOK_NAME_1]", "[TOK_PHONE_1]"]


async def test_json_never_mutates_its_input_and_never_hydrates_keys():
    payload = {"[TOK_NAME_1]": "[TOK_NAME_1]", "list": ["[TOK_NAME_1]"]}
    before = copy.deepcopy(payload)
    out = await dj(payload)
    assert payload == before
    assert out == {"[TOK_NAME_1]": "John Doe", "list": ["John Doe"]}


async def test_json_leaves_unknown_tokens_and_returns_early_when_there_are_none():
    v = StubVault()
    out = await dj({"a": "[TOK_NAME_9] and [TOK_NAME_1]"}, v)
    assert out == {"a": "[TOK_NAME_9] and John Doe"}
    v2 = StubVault()
    assert await dj({"a": "nothing here", "b": [1, 2]}, v2) == {"a": "nothing here", "b": [1, 2]} and v2.calls == []


async def test_json_bounds_depth_and_size():
    deep: dict = {}
    node = deep
    for _ in range(MAX_DEPTH + 5):
        node["x"] = {}
        node = node["x"]
    with pytest.raises(ValueError):
        await dj(deep)
    with pytest.raises(ValueError):
        await dj({"a": ["x"] * 250_000})


async def test_json_outage_raises_by_default_and_can_pass_through():
    down = StubVault(fail=True)
    payload = {"a": "[TOK_NAME_1]"}
    with pytest.raises(VaultUnavailable):
        await dj(payload, down)
    assert await dj(payload, down, on_unavailable="passthrough") == payload


# ------------------------------------------------------------------ against the real vault (fakeredis)
async def test_end_to_end_tokenize_then_stream_and_json_with_the_real_vault(vault, ref):
    name, email = await vault.tokenize_many(ref, [("NAME", "John Doe"), ("EMAIL", "john.doe@example.com")])
    other = type(ref)("org-1", "someone-elses-session")
    intruder = await vault.tokenize(other, "NAME", "Mallory")

    chunks = ["Dear ", name[:4], name[4:], ", we wrote to ", email[:-3], email[-3:], ". Also ", intruder, "."]
    st = StreamState()
    out = "".join([await detokenize_stream(c, ref.session_id, vault=vault, org_id=ref.org_id, state=st) for c in chunks]
                  + [await detokenize_stream("", ref.session_id, vault=vault, org_id=ref.org_id, state=st, final=True)])
    # `intruder` has the same text as `name` ([TOK_NAME_1]) but belongs to another session: it must resolve to THIS session's value.
    assert out == "Dear John Doe, we wrote to john.doe@example.com. Also John Doe."
    assert "Mallory" not in out

    j = await detokenize_json({"msg": f"hi {name}", "list": [email]}, ref.session_id, vault=vault, org_id=ref.org_id)
    assert j == {"msg": "hi John Doe", "list": ["john.doe@example.com"]}
    wrong = await detokenize_json({"msg": f"hi {name}"}, "unrelated-session", vault=vault, org_id=ref.org_id)
    assert wrong == {"msg": f"hi {name}"}                       # another session cannot hydrate this session's tokens
    other_org = await detokenize_json({"msg": f"hi {name}"}, ref.session_id, vault=vault, org_id="org-2")
    assert other_org == {"msg": f"hi {name}"}
