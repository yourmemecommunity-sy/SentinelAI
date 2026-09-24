# token-vault

Reversible tokenization for a policy that says `TOKENIZE`: the model sees `[TOK_EMAIL_1]`, the caller gets the real address back.
Internal service (Python / FastAPI / Redis). Never expose it to clients: `/v1/vault/resolve` returns plaintext.

## What it guarantees (each has a test)
| Property | How |
|---|---|
| Same value -> same token inside a session, even with concurrent writers | HMAC-SHA256 digest as the lookup key, `HSETNX` decides the winner, losers clean up |
| A token means nothing outside its session | Keys derived per (tenant, session) with HKDF; the same value elsewhere yields an unrelated digest and ciphertext |
| Encrypted at rest | AES-256-GCM per value, token as AAD; a Redis dump holds no plaintext and no user-supplied ids |
| Hard retention | Three Hashes per session, `EXPIREAT` on an **absolute** deadline fixed at creation (default 3600 s): activity and reads cannot extend it |
| Credentials never enter | Default-deny allow-list of entity types (cross-checked against the engine's credential/card/threat sets) |
| Resilient | Per-operation timeout, one jittered retry, circuit breaker; outage -> `VaultUnavailable` (callers fail closed, hydration degrades to leaving tokens) |
| Bounded | Per-session token cap, value size cap, batch cap, body cap, JSON depth/node caps |

## Redis schema
```
sentinel:vault:v1:{<sid>}:fwd    HASH  digest(type, normalized value) -> token
sentinel:vault:v1:{<sid>}:rev    HASH  token -> sealed value
sentinel:vault:v1:{<sid>}:meta   HASH  kid, deadline, ctr:<TYPE>
```
`<sid>` = SHA-256(tenant, session): ids never appear in the keyspace. The hash tag keeps a session on one Redis Cluster shard.

## API (all need `X-Internal-Token`)
`POST /v1/vault/tokenize` · `POST /v1/vault/resolve` · `POST /v1/vault/detokenize` · `DELETE /v1/vault/sessions` · `GET /health` · `GET /ready`

The library functions are `detokenize_json(payload, session_id, *, vault, org_id)` and `detokenize_stream(chunk, session_id, *, vault, org_id, state)`.
The stream function is stateful (`StreamState`): a token split across chunks is held back (at most 44 characters) and everything else is released immediately.

## Configuration
`VAULT_TOKEN`, `VAULT_MASTER_KEYS` (`k1:<base64>,k2:<base64>`, each >= 32 bytes), `VAULT_ACTIVE_KEY`, `REDIS_URL`, `VAULT_TTL_SECONDS` (default 3600, max 86400), limits and timeouts (see `app/config/settings.py`).
`SENTINEL_ENV=production` refuses to start without a token, master keys, or with `VAULT_BACKEND=memory`. A session is pinned to the key id it started with, so after rotating, keep the previous key for at least one TTL.

## Tests
```
pip install -e ".[dev]"   # includes fakeredis
python -m pytest          # 109 tests
```

## Known limitations
- **Never run against a real Redis server** (none available on the dev machine): tests use fakeredis, plus a wrapper that forces task interleaving so the race handling really executes. Cluster behaviour, `EXPIREAT` under real Redis time and persistence settings are unverified. Disable RDB/AOF persistence (or encrypt the volume) if the retention mandate must hold on disk.
- Anyone holding `VAULT_MASTER_KEYS` **and** Redis access can decrypt live sessions. Keep the keys in a secret manager, not next to Redis.
- Tokens are plain text in the model's context, so a model can repeat them (that is the point) but cannot invent values: unknown tokens stay tokens.
- Session ids chosen by a client are namespaced by the gateway per caller, but the vault itself trusts the tenant/session it is given: only the gateway may call it.
