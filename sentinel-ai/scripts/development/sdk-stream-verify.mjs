#!/usr/bin/env node
/**
 * Streams through the JavaScript SDK against the REAL containerized gateway and a REAL model (Ollama). The SDK's own test
 * suite uses protocol-faithful HTTP test servers; this is the check that the SDK and the actual gateway agree.
 *
 *   docker run --rm --network sentinel-ai_frontend -e OLLAMA_MODEL=... -v "$PWD/packages/sdk/javascript:/sdk:ro" \
 *     -v "$PWD/scripts/development:/s:ro" node:20-alpine node /s/sdk-stream-verify.mjs
 *
 * Prints PASS/FAIL per check and "KEY=<api key>" for the Python run that follows (a throwaway organization's key).
 */
import { SentinelAI, SentinelBlockedError } from "/sdk/dist/index.js";

const API = process.env.API_URL ?? "http://api:4000";
const MODEL = process.env.OLLAMA_MODEL;
const AWS = "AK" + "IA" + "ABCDEFGHIJKLMNOP";           // runtime-assembled, not a real credential
let failures = 0;
const check = (name, ok, detail = "") => { console.log(`${ok ? "PASS" : "FAIL"} ${name}${detail ? `  (${detail})` : ""}`); if (!ok) failures++; };

if (!MODEL) { console.log("SKIP OLLAMA_MODEL is not set: no real model to stream from"); process.exit(3); }

const post = async (path, body, headers = {}) => {
  const r = await fetch(`${API}${path}`, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify(body) });
  return r.json();
};
const slug = `sdk-${Date.now().toString(36)}`;
const s = await post("/v1/auth/signup", { organization_name: slug, email: `${slug}@example.com`, password: "Str0ng-Sdk-Passw0rd!" });
const k = await post("/v1/api-keys", { name: "sdk", role: "DEVELOPER" }, { authorization: `Bearer ${s.access_token}` });
// TOKENIZE email, so the stream exercises the vault and hydration end to end.
await post("/v1/policies", { policy_id: "sdk-tokenize", rules: [{ entity: "EMAIL", action: "TOKENIZE" }] }, { authorization: `Bearer ${s.access_token}` });

// Plain http is refused by default (the key would travel in clear text); this is a private Docker network.
const client = new SentinelAI({ apiKey: k.key, baseUrl: API, timeoutMs: 120_000, allowInsecureHttp: true });

// 1. A normal stream: text arrives in pieces and the summary reports the real model and both security verdicts.
const stream = client.stream({ provider: "ollama", model: MODEL, maxOutputTokens: 30, sessionId: "sdk-verify",
  messages: [{ role: "user", content: "Say hello to jane.doe@example.com in one short sentence." }] });
const parts = [];
for await (const t of stream) parts.push(t);
const summary = await stream.summary;
check("JS SDK streams from the real gateway and a real model", parts.length > 0 && parts.join("").length > 0, `${parts.length} deltas`);
check("the summary reports the real model and both security verdicts",
  summary.model === MODEL && !!summary.security?.input?.eventId && !!summary.security?.output?.eventId,
  `model=${summary.model} input=${summary.security?.input?.decision} output=${summary.security?.output?.decision}`);
check("PII in the prompt was TOKENIZED before the model saw it", summary.security?.input?.decision === "TOKENIZE", summary.security?.input?.decision);
check("hydration was applied through the real token vault", summary.hydration === "applied", summary.hydration);

// 2. A secret in the prompt: blocked before any stream opens, surfaced as a typed error.
let err = null;
try { for await (const _t of client.stream({ provider: "ollama", model: MODEL, messages: [{ role: "user", content: `deploy with ${AWS}` }] })) { /* never */ } }
catch (e) { err = e; }
check("a secret in a streamed prompt raises SentinelBlockedError (input stage, nothing streamed)",
  err instanceof SentinelBlockedError && err.stage === "input", err ? `${err.name} stage=${err.stage}` : "no error");

// 3. Breaking out early ends the request cleanly (the SDK aborts upstream).
let n = 0;
const early = client.stream({ provider: "ollama", model: MODEL, maxOutputTokens: 60, messages: [{ role: "user", content: "Count from one to twenty in words." }] });
// Break after the FIRST delta: the gateway holds back up to 256 characters, so a short reply may be a single delta.
for await (const _t of early) { if (++n === 1) break; }
let summaryErr = null;
try { await early.summary; } catch (e) { summaryErr = e; }
check("breaking out early is not reported as a complete reply", summaryErr !== null, summaryErr?.name ?? "summary resolved");

console.log(`KEY=${k.key}`);
process.exit(failures === 0 ? 0 : 1);
