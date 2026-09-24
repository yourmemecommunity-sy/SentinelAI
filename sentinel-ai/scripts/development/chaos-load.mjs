#!/usr/bin/env node
/**
 * Continuous load for chaos testing (scripts/development/chaos.sh injects the faults while this runs).
 *
 *   node chaos-load.mjs <seconds> <apiKey> <outFile>
 *
 * Sends, in a loop and concurrently: scans of text containing a (synthetic) secret, allow/deny checks of the same text,
 * and scans of clean text. Every response is classified against the fail-closed invariant:
 *
 *   A request carrying a secret must NEVER receive a verdict that lets content through (decision other than BLOCK /
 *   QUARANTINE, sanitized text containing the secret, allowed=true). Refusals (403/429/503) are fine - that is failing
 *   closed. A 5xx other than 503 or a request that hangs past the client timeout is recorded as a defect.
 *
 * Writes one JSON line per request to <outFile> and prints a summary per second, so faults can be correlated in time.
 */
import { appendFileSync, writeFileSync } from "node:fs";

const [secondsArg, KEY, OUT] = process.argv.slice(2);
const API = process.env.API_URL ?? "http://api:4000";
const SECONDS = Number(secondsArg ?? 120);
const AWS = "AK" + "IA" + "ABCDEFGHIJKLMNOP";                       // runtime-assembled, not a real credential
const SECRET_TEXT = `deploy with ${AWS} tonight`;
const EMAIL = "jane.doe@example.com";
const TIMEOUT_MS = 15_000;
// Paced to stay under the gateway's production rate limit (600/min per client IP), so every request is actually processed
// by the pipeline instead of being answered 429 at the door - a 429 proves nothing about fail-closed behaviour.
const WORKERS = 6;
const PER_WORKER_INTERVAL_MS = 750;                                     // 6 workers -> ~8 requests/s
writeFileSync(OUT, "");

const kinds = [
  { kind: "scan-secret", path: "/v1/security/scan", body: { text: SECRET_TEXT } },
  { kind: "check-secret", path: "/v1/security/check", body: { text: SECRET_TEXT } },
  { kind: "scan-clean", path: "/v1/security/scan", body: { text: "summarize the quarterly roadmap" } },
  // The test organization's policy TOKENIZEs email: this request needs the token vault.
  { kind: "scan-tokenize", path: "/v1/security/scan", body: { text: `contact ${EMAIL} about the renewal` } },
];

function classify(kind, status, json) {
  if (status === -1) return "timeout";                                 // no answer within the client timeout: a hang
  if (status === 0) return "conn_error";                               // connection refused/reset (e.g. gateway restarting)
  if (status >= 500 && status !== 503) return "server_error";
  if (kind === "scan-tokenize") {
    // Invariant: the raw address never comes back; with the vault down the request must fail closed, not pass raw.
    if (status !== 200) return `refused_${status}`;
    if ((json?.sanitized_text ?? "").includes(EMAIL) || json?.decision === "ALLOW") return "LEAK";
    return json?.failed_closed ? "blocked_failclosed" : "tokenized";
  }
  if (!kind.endsWith("secret")) return status === 200 ? "ok" : `refused_${status}`;
  if (status !== 200) return `refused_${status}`;
  if (kind === "check-secret") return json?.allowed === false ? "blocked" : "LEAK";
  const leaked = !["BLOCK", "QUARANTINE"].includes(json?.decision) || (json?.sanitized_text ?? "").includes(AWS);
  return leaked ? "LEAK" : json?.failed_closed ? "blocked_failclosed" : "blocked";
}

const t0 = Date.now();
const counts = {};
let second = 0;
async function worker(i) {
  let n = i;
  while (Date.now() - t0 < SECONDS * 1000) {
    const k = kinds[n++ % kinds.length];
    const started = Date.now();
    let status = 0, json = null;
    try {
      const res = await fetch(`${API}${k.path}`, { method: "POST", headers: { "x-sentinel-api-key": KEY, "content-type": "application/json" },
        body: JSON.stringify(k.body), signal: AbortSignal.timeout(TIMEOUT_MS) });
      status = res.status;
      try { json = await res.json(); } catch { /* non-JSON */ }
    } catch (e) { status = e?.name === "TimeoutError" || e?.name === "AbortError" ? -1 : 0; }
    const cls = classify(k.kind, status, json);
    const rec = { t: Math.round((started - t0) / 100) / 10, at: started, kind: k.kind, status, cls, ms: Date.now() - started, reason: json?.fail_closed_reason ?? json?.reason ?? json?.error ?? null };
    appendFileSync(OUT, JSON.stringify(rec) + "\n");
    counts[cls] = (counts[cls] ?? 0) + 1;
    const wait = PER_WORKER_INTERVAL_MS - (Date.now() - started);
    if (wait > 0) await new Promise((r) => setTimeout(r, wait));
  }
}
const ticker = setInterval(() => { second += 5; console.log(`t=${second}s ${JSON.stringify(counts)}`); }, 5000);
/**
 * Optional (CHAT_PROVIDER=ollama): one slow worker sends real chats WITH a session_id through a real model. With the
 * organization's TOKENIZE policy these need the token vault, so they are what a vault outage actually affects.
 * chaos.sh checks that none of them succeeds while the vault is down.
 */
async function chatWorker() {
  const provider = process.env.CHAT_PROVIDER;
  if (!provider) return;
  while (Date.now() - t0 < SECONDS * 1000) {
    const started = Date.now();
    let status = 0, json = null;
    try {
      const res = await fetch(`${API}/v1/ai/chat`, { method: "POST", headers: { "x-sentinel-api-key": KEY, "content-type": "application/json" },
        body: JSON.stringify({ provider, session_id: "chaos-session", max_output_tokens: 4,
          messages: [{ role: "user", content: `Reply with the word OK. Customer: ${EMAIL}` }] }), signal: AbortSignal.timeout(60_000) });
      status = res.status;
      try { json = await res.json(); } catch { /* non-JSON */ }
    } catch (e) { status = e?.name === "TimeoutError" || e?.name === "AbortError" ? -1 : 0; }
    const cls = status === -1 ? "timeout" : status === 0 ? "conn_error" : status >= 500 && status !== 503 && status !== 502 ? "server_error"
      : status === 200 ? (json?.security?.input?.decision === "ALLOW" ? "LEAK" : "chat_ok") : `refused_${status}`;
    appendFileSync(OUT, JSON.stringify({ t: Math.round((started - t0) / 100) / 10, at: started, kind: "chat-tokenize", status, cls, ms: Date.now() - started,
      reason: json?.reason ?? json?.error ?? null }) + "\n");
    counts[cls] = (counts[cls] ?? 0) + 1;
    const wait = 1500 - (Date.now() - started);
    if (wait > 0) await new Promise((r) => setTimeout(r, wait));
  }
}
await Promise.all([...Array.from({ length: WORKERS }, (_, i) => worker(i)), chatWorker()]);
clearInterval(ticker);
console.log(`FINAL ${JSON.stringify(counts)}`);
