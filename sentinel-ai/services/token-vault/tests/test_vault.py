import asyncio
import dataclasses

import pytest

from app.backend import key
from app.crypto import KeyRing
from app.errors import TokenizationRefused, VaultLimitExceeded
from app.tokens import is_token
from app.vault import SessionRef
from tests.conftest import KEY1, KEY2

JOHN, JANE = "John Doe", "jane.roe@example.com"


async def dump(redis) -> bytes:
    """Every byte Redis holds: keys, fields and values."""
    out = bytearray()
    for k in await redis.keys("*"):
        out += k
        for f, v in (await redis.hgetall(k)).items():
            out += f + b"=" + v + b"\n"
    return bytes(out)


# ------------------------------------------------------------------ determinism
async def test_same_value_same_token_and_numbers_count_per_type(vault, ref):
    a = await vault.tokenize(ref, "NAME", JOHN)
    b = await vault.tokenize(ref, "NAME", "Mary Major")
    c = await vault.tokenize(ref, "NAME", JOHN)
    e = await vault.tokenize(ref, "EMAIL", JANE)
    assert (a, b, c, e) == ("[TOK_NAME_1]", "[TOK_NAME_2]", "[TOK_NAME_1]", "[TOK_EMAIL_1]")


async def test_batch_tokenize_dedupes_and_keeps_order(vault, ref):
    toks = await vault.tokenize_many(ref, [("NAME", JOHN), ("EMAIL", JANE), ("NAME", JOHN), ("NAME", "Mary Major"), ("EMAIL", JANE)])
    assert toks == ["[TOK_NAME_1]", "[TOK_EMAIL_1]", "[TOK_NAME_1]", "[TOK_NAME_2]", "[TOK_EMAIL_1]"]
    assert await vault.tokenize_many(ref, []) == []


async def test_spelling_variants_map_to_one_token_and_restore_the_first_spelling(vault, ref):
    t1 = await vault.tokenize(ref, "NAME", "John Doe")
    t2 = await vault.tokenize(ref, "NAME", "  john   DOE ")
    p1 = await vault.tokenize(ref, "PHONE", "+1 (415) 555-0132")
    p2 = await vault.tokenize(ref, "PHONE", "1 415 555 0132")
    assert t1 == t2 and p1 == p2
    assert await vault.resolve(ref, [t1, p1]) == {t1: "John Doe", p1: "+1 (415) 555-0132"}


async def test_concurrent_writers_agree_on_one_token(racing_vault, ref, redis):
    toks = await asyncio.gather(*[racing_vault.tokenize(ref, "NAME", JOHN) for _ in range(60)])
    assert len(set(toks)) == 1                                  # 60 writers raced; exactly one mapping won
    winner = toks[0]
    assert await racing_vault.resolve(ref, [winner]) == {winner: JOHN}
    assert await redis.hlen(key(ref.sid, "rev")) == 1          # the 59 losers removed their orphaned sealed copies
    assert await redis.hlen(key(ref.sid, "fwd")) == 1


async def test_concurrent_distinct_values_get_unique_gapless_numbers(racing_vault, ref):
    vault = racing_vault
    values = [f"Person Number {i}" for i in range(80)]
    toks = await asyncio.gather(*[vault.tokenize(ref, "NAME", v) for v in values])
    assert sorted(int(t.rsplit("_", 1)[1][:-1]) for t in toks) == list(range(1, 81))
    resolved = await vault.resolve(ref, toks)
    assert {resolved[t] for t in toks} == set(values) and all(resolved[t] == v for t, v in zip(toks, values))


async def test_a_burst_above_the_default_pool_cap_queues_instead_of_failing_closed(racing_vault, ref):
    # 300 in-flight operations exceed redis-py's default 100-connection pool, which RAISES when full (a ConnectionError, so
    # the vault would report an outage). The blocking pool makes the burst queue: every request is served.
    toks = await asyncio.gather(*[racing_vault.tokenize(ref, "NAME", f"Burst Person {i}") for i in range(300)])
    assert len(set(toks)) == 300


async def test_mixed_concurrent_load_stays_consistent(racing_vault, ref, redis):
    vault = racing_vault
    values = [f"Value {i}" for i in range(20)]
    toks = await asyncio.gather(*[vault.tokenize(ref, "NAME", values[i % 20]) for i in range(200)])
    by_value: dict[str, set[str]] = {}
    for i, t in enumerate(toks):
        by_value.setdefault(values[i % 20], set()).add(t)
    assert all(len(s) == 1 for s in by_value.values())            # each value -> exactly one token
    assert len({next(iter(s)) for s in by_value.values()}) == 20  # ...and tokens are not shared between values
    assert await redis.hlen(key(ref.sid, "rev")) == 20


# ------------------------------------------------------------------ isolation
async def test_sessions_and_tenants_are_isolated(vault):
    a, b, other_org = SessionRef("org-1", "s1"), SessionRef("org-1", "s2"), SessionRef("org-2", "s1")
    ta = await vault.tokenize(a, "NAME", JOHN)
    tb = await vault.tokenize(b, "NAME", "Someone Else")
    to = await vault.tokenize(other_org, "NAME", "Third Person")
    assert ta == tb == to == "[TOK_NAME_1]"                       # same token text, three unrelated meanings
    assert await vault.resolve(a, [ta]) == {ta: JOHN}
    assert await vault.resolve(b, [ta]) == {ta: "Someone Else"}
    assert await vault.resolve(other_org, [ta]) == {ta: "Third Person"}
    assert await vault.resolve(SessionRef("org-1", "never-used"), [ta]) == {}


async def test_a_token_from_another_session_never_resolves_to_that_sessions_value(vault):
    a, b = SessionRef("org-1", "s1"), SessionRef("org-1", "s2")
    await vault.tokenize_many(a, [("NAME", "Alpha"), ("EMAIL", "alpha@example.com")])
    (only_a,) = await vault.tokenize_many(a, [("PHONE", "+1 415 555 0100")])
    await vault.tokenize(b, "NAME", "Beta")
    assert await vault.resolve(b, [only_a]) == {}                 # b has no PHONE token; a's value must not appear


async def test_redis_holds_no_plaintext_and_no_user_supplied_ids(vault, redis):
    ref = SessionRef("acme-corp", "user-supplied-session-id")
    await vault.tokenize_many(ref, [("NAME", JOHN), ("EMAIL", JANE), ("PHONE", "+1 415 555 0132")])
    raw = (await dump(redis)).lower()
    for secret in [b"john", b"doe", b"jane", b"roe", b"example.com", b"555 0132", b"14155550132", b"acme-corp", b"user-supplied-session-id"]:
        assert secret not in raw, secret


async def test_same_value_in_another_session_leaves_unrelated_ciphertext_and_lookup_keys(vault, redis):
    r1, r2 = SessionRef("o", "s1"), SessionRef("o", "s2")
    await vault.tokenize(r1, "NAME", JOHN)
    await vault.tokenize(r2, "NAME", JOHN)
    f1, f2 = await redis.hkeys(key(r1.sid, "fwd")), await redis.hkeys(key(r2.sid, "fwd"))
    v1, v2 = await redis.hvals(key(r1.sid, "rev")), await redis.hvals(key(r2.sid, "rev"))
    assert f1 != f2 and v1 != v2


async def test_a_different_master_key_cannot_read_existing_sessions(make_vault, ref):
    tok = await make_vault().tokenize(ref, "NAME", JOHN)
    wrong = make_vault(ring=KeyRing({"k1": KEY2}, "k1"))
    assert await wrong.resolve(ref, [tok]) == {}                   # fails to authenticate: unresolved, never an exception


# ------------------------------------------------------------------ retention
async def test_ttl_is_applied_to_all_three_hashes(vault, ref, redis):
    await vault.tokenize(ref, "NAME", JOHN)
    for part in ("fwd", "rev", "meta"):
        assert 3590 <= await redis.ttl(key(ref.sid, part)) <= 3601, part


async def test_activity_cannot_extend_the_absolute_deadline(vault, ref, redis, clock):
    # The fake clock cannot move Redis's own clock, so this checks the *absolute* deadline instead: had a later write
    # re-armed the TTL from "now + ttl", EXPIREAT would land at t0 + 1000 + 3600 (TTL ~4600 by Redis's clock).
    await vault.tokenize(ref, "NAME", JOHN)
    clock.advance(1000)
    await vault.tokenize(ref, "EMAIL", JANE)
    for part in ("fwd", "rev", "meta"):
        assert 3590 <= await redis.ttl(key(ref.sid, part)) <= 3601, part


async def test_reads_do_not_touch_the_ttl(vault, ref, redis):
    tok = await vault.tokenize(ref, "NAME", JOHN)
    for part in ("fwd", "rev", "meta"):
        await redis.expire(key(ref.sid, part), 100)
    for _ in range(5):
        assert await vault.resolve(ref, [tok]) == {tok: JOHN}
    for part in ("fwd", "rev", "meta"):
        assert await redis.ttl(key(ref.sid, part)) <= 100, part


async def test_past_the_deadline_nothing_resolves_even_if_redis_has_not_evicted_yet(vault, ref, clock):
    tok = await vault.tokenize(ref, "NAME", JOHN)
    clock.advance(3601)
    assert await vault.resolve(ref, [tok]) == {}


async def test_writing_after_expiry_starts_a_fresh_session(vault, ref, clock):
    old = await vault.tokenize(ref, "NAME", JOHN)
    clock.advance(3601)
    new = await vault.tokenize(ref, "NAME", "Fresh Person")
    assert new == old == "[TOK_NAME_1]"                            # numbering restarted: the old mapping is gone
    assert await vault.resolve(ref, [new]) == {new: "Fresh Person"}


async def test_redis_really_evicts_after_the_ttl(make_vault, settings, redis):
    v = make_vault(s=dataclasses.replace(settings, ttl_seconds=1))
    # this test uses the real clock so the fakeredis expiry actually runs
    v._b.now = __import__("time").time
    r = SessionRef("o", "short-lived")
    tok = await v.tokenize(r, "NAME", JOHN)
    assert await v.resolve(r, [tok]) == {tok: JOHN}
    await asyncio.sleep(2.6)
    assert await redis.keys("*") == []


async def test_delete_session_removes_everything(vault, ref, redis):
    tok = await vault.tokenize(ref, "NAME", JOHN)
    await vault.delete_session(ref)
    assert await redis.keys("*") == [] and await vault.resolve(ref, [tok]) == {}


# ------------------------------------------------------------------ what may enter the vault
@pytest.mark.parametrize("entity", ["API_KEY", "AWS_CREDENTIAL", "PASSWORD", "PRIVATE_KEY", "JWT", "CREDIT_CARD", "PROMPT_INJECTION", "SECRET", "TOK", ""])
async def test_credentials_secrets_cards_and_unknown_types_are_refused_and_nothing_is_stored(vault, ref, redis, entity):
    with pytest.raises(TokenizationRefused):
        await vault.tokenize(ref, entity, "sk-live-not-a-real-value")
    assert await redis.keys("*") == []


async def test_a_refused_item_refuses_the_whole_batch_atomically(vault, ref, redis):
    with pytest.raises(TokenizationRefused):
        await vault.tokenize_many(ref, [("NAME", JOHN), ("PASSWORD", "hunter2")])
    assert await redis.keys("*") == []


async def test_bad_input_is_refused(vault, ref):
    for entity, value in [("NAME", ""), ("NAME", "   "), ("name", "x")]:
        with pytest.raises(TokenizationRefused):
            await vault.tokenize(ref, entity, value)
    for org, sess in [("", "s"), ("o", ""), ("o" * 129, "s"), ("o o", "s"), ("o", "s\n"), ("o", "s/../x"), ("o\x00", "s")]:
        with pytest.raises(TokenizationRefused):
            SessionRef(org, sess)


async def test_limits(make_vault, settings, ref):
    v = make_vault(s=dataclasses.replace(settings, max_tokens_per_session=3, max_batch=4, max_value_bytes=16))
    await v.tokenize_many(ref, [("NAME", "a1"), ("NAME", "a2"), ("NAME", "a3")])
    with pytest.raises(VaultLimitExceeded):
        await v.tokenize(ref, "NAME", "a4")
    assert await v.tokenize(ref, "NAME", "a1") == "[TOK_NAME_1]"    # existing values keep working at the cap
    with pytest.raises(VaultLimitExceeded):
        await v.tokenize_many(SessionRef("o", "batch"), [("NAME", f"n{i}") for i in range(5)])
    with pytest.raises(VaultLimitExceeded):
        await v.tokenize(SessionRef("o", "big"), "NAME", "x" * 17)
    with pytest.raises(VaultLimitExceeded):
        await v.tokenize(SessionRef("o", "big"), "NAME", "é" * 9)   # 18 bytes: the cap is in bytes, not characters


# ------------------------------------------------------------------ resolve
async def test_resolve_ignores_junk_and_unknown_tokens(vault, ref):
    tok = await vault.tokenize(ref, "NAME", JOHN)
    got = await vault.resolve(ref, [tok, "[TOK_NAME_99]", "not a token", "[TOK_PASSWORD_1]", "", tok])
    assert got == {tok: JOHN}
    assert await vault.resolve(ref, []) == {}


async def test_resolve_caps_the_batch(make_vault, settings, ref):
    v = make_vault(s=dataclasses.replace(settings, max_batch=3))
    toks = [await v.tokenize(ref, "NAME", f"n{i}") for i in range(3)]
    many = toks + [f"[TOK_NAME_{i}]" for i in range(10, 200)]
    assert set(await v.resolve(ref, many)) == set(toks)


async def test_a_corrupted_entry_is_unresolved_not_fatal(vault, ref, redis):
    good = await vault.tokenize(ref, "EMAIL", JANE)
    bad = await vault.tokenize(ref, "NAME", JOHN)
    await redis.hset(key(ref.sid, "rev"), bad, b"\x03k1\x00garbage")
    assert await vault.resolve(ref, [good, bad]) == {good: JANE}


# ------------------------------------------------------------------ key rotation
async def test_sessions_are_pinned_to_the_key_they_started_with(make_vault, redis, ref):
    old_ring = KeyRing({"k1": KEY1}, "k1")
    new_ring = KeyRing({"k1": KEY1, "k2": KEY2}, "k2")                 # rotation: k2 active, k1 kept for running sessions
    t1 = await make_vault(ring=old_ring).tokenize(ref, "NAME", JOHN)
    rotated = make_vault(ring=new_ring)
    assert await rotated.resolve(ref, [t1]) == {t1: JOHN}              # old session still readable
    assert await rotated.tokenize(ref, "NAME", JOHN) == t1             # ...and still deterministic (same digest key)
    t2 = await rotated.tokenize(ref, "EMAIL", JANE)
    assert await rotated.resolve(ref, [t1, t2]) == {t1: JOHN, t2: JANE}
    assert (await redis.hget(key(ref.sid, "meta"), "kid")) == b"k1"
    fresh = SessionRef("org-1", "brand-new")
    await rotated.tokenize(fresh, "NAME", JOHN)
    assert (await redis.hget(key(fresh.sid, "meta"), "kid")) == b"k2"  # new sessions use the active key


async def test_a_session_whose_key_was_retired_is_unreadable_and_unwritable(make_vault, ref):
    tok = await make_vault(ring=KeyRing({"k1": KEY1}, "k1")).tokenize(ref, "NAME", JOHN)
    only_k2 = make_vault(ring=KeyRing({"k2": KEY2}, "k2"))
    assert await only_k2.resolve(ref, [tok]) == {}
    with pytest.raises(TokenizationRefused):
        await only_k2.tokenize(ref, "NAME", "New")


def test_tokens_returned_are_always_valid_tokens():
    assert is_token("[TOK_NAME_1]")
