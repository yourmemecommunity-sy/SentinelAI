#!/usr/bin/env node
/**
 * Input fuzzing of the RUNNING gateway: every write endpoint receives malformed, hostile and edge-case payloads.
 *
 *   docker run --rm --network sentinel-ai_frontend -v "$PWD/scripts/development:/s:ro" node:20-alpine node /s/api-fuzz.mjs
 *
 * Invariants checked on EVERY response:
 *   - no 5xx (a malformed request is the client's fault: it must be rejected, never crash or half-process);
 *   - answered within 10 s (no hang);
 *   - a 4xx carries a JSON body with an `error` code;
 *   - no stack trace, file path or exception name in the body;
 *   - the unique marker planted in each payload is never reflected back (validation errors must not echo input).
 * Paced below the per-IP rate limit (600/min) so the pipeline, not the limiter, answers. /v1/auth/* has a stricter
 * limiter (20/min), so those routes are expected to reach 429 part-way; 429 is a valid rejection.
 */
const API = process.env.API_URL ?? "http://api:4000";
const MARK = "FZ" + Math.random().toString(36).slice(2, 10).toUpperCase();
let failures = 0, sent = 0;
const statuses = {};
const problems = [];

async function req(method, path, { body, raw, ctype = "application/json", headers = {} } = {}) {
  const t0 = Date.now();
  const h = { ...headers };
  if (body !== undefined || raw !== undefined) h["content-type"] = ctype;
  try {
    const res = await fetch(`${API}${path}`, { method, headers: h, body: raw ?? (body !== undefined ? JSON.stringify(body) : undefined), signal: AbortSignal.timeout(10_000) });
    const text = await res.text();
    return { status: res.status, text, ms: Date.now() - t0 };
  } catch (e) {
    return { status: e?.name === "TimeoutError" ? -1 : 0, text: String(e), ms: Date.now() - t0 };
  }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const PACE_MS = 115;                                            // ~8.7 req/s: under 600/min

function judge(label, r) {
  sent++;
  statuses[r.status] = (statuses[r.status] ?? 0) + 1;
  const bad = [];
  if (r.status === -1) bad.push("HUNG (>10s)");
  else if (r.status === 0) bad.push("connection error");
  else if (r.status >= 500) bad.push(`HTTP ${r.status}`);
  if (r.status >= 400 && r.status < 500 && r.status !== 413) {
    try { if (typeof JSON.parse(r.text).error !== "string") bad.push("4xx without an error code"); }
    catch { bad.push("4xx body is not JSON"); }
  }
  if (/\bat \S+\.(js|ts|mjs|py):\d+|Traceback|node_modules|\/app\/|TypeError|ReferenceError|SyntaxError: /.test(r.text)) bad.push("internal detail leaked");
  // The rule is that ERRORS never echo input. Successful responses legitimately return data: a scan returns the sanitized
  // text it scanned, a create returns the stored resource (a team's own name).
  if (r.status >= 400 && r.text.includes(MARK)) bad.push("input reflected in an error response");
  if (bad.length) { failures++; problems.push({ label, status: r.status, bad, body: r.text.slice(0, 300) }); }
}

// ---------------------------------------------------------------- credentials for the authenticated routes
const slug = `fuzz-${Date.now().toString(36)}`;
const s = JSON.parse((await req("POST", "/v1/auth/signup", { body: { organization_name: slug, email: `${slug}@example.com`, password: "Str0ng-Fuzz-Passw0rd!" } })).text);
const jwt = s.access_token;
const key = JSON.parse((await req("POST", "/v1/api-keys", { body: { name: "fuzz", role: "DEVELOPER" }, headers: { authorization: `Bearer ${jwt}` } })).text).key;
if (!jwt || !key) { console.log("FAIL could not create a fuzzing organization"); process.exit(2); }
const K = { "x-sentinel-api-key": key };
const J = { authorization: `Bearer ${jwt}` };
const UUID = "11111111-1111-4111-8111-111111111111";

// ---------------------------------------------------------------- payloads
const deep = (n) => { let o = { v: MARK }; for (let i = 0; i < n; i++) o = { a: o }; return o; };
const long = (n) => MARK + "x".repeat(n);
const values = [
  null, true, 0, -1, 1e308, -0, 2 ** 53 + 1, "", MARK, long(10_000), [], [MARK], {}, { [MARK]: MARK },
  "‮" + MARK + "​‍﻿", "\uD800" + MARK, "\u0000" + MARK + "\u0007", "<script>" + MARK + "</script>",
  "' OR 1=1 --" + MARK, "${7*7}" + MARK, "../../etc/passwd" + MARK, "%00" + MARK, "NaN", "Infinity",
];
function* bodies(fields) {
  yield { raw: "{" + MARK, label: "truncated JSON" };
  yield { raw: "", label: "empty body" };
  yield { raw: "null", label: "JSON null" };
  yield { raw: `["${MARK}"]`, label: "JSON array" };
  yield { raw: `"${MARK}"`, label: "JSON string" };
  yield { raw: `{"a":1}`, ctype: "text/plain", label: "wrong content-type" };
  yield { raw: `<a>${MARK}</a>`, ctype: "application/xml", label: "xml" };
  yield { raw: Buffer.from([0xff, 0xfe, 0xfd, 0x7b]), label: "invalid UTF-8" };
  yield { body: deep(2000), label: "2000-deep nesting" };
  yield { raw: `{"__proto__":{"polluted":"${MARK}"},"constructor":{"prototype":{"x":1}}}`, label: "prototype pollution keys" };
  yield { body: { ...Object.fromEntries(fields.map((f) => [f, MARK])), [`extra_${MARK}`]: 1 }, label: "unknown extra field" };
  for (const f of fields) for (const v of values) yield { body: { [f]: v }, label: `${f}=${JSON.stringify(v)?.slice(0, 30)}` };
}

const targets = [
  ["POST", "/v1/security/scan", K, ["text", "direction", "context"]],
  ["POST", "/v1/security/check", K, ["text", "direction"]],
  ["POST", "/v1/ai/chat", K, ["provider", "messages", "model", "session_id", "max_output_tokens", "temperature"]],
  ["POST", "/v1/ai/generate", K, ["provider", "prompt"]],
  ["POST", "/v1/ai/stream", K, ["provider", "messages", "mode"]],
  ["POST", "/v1/policies", J, ["policy_id", "rules"]],
  ["PUT", `/v1/policies/${MARK}`, J, ["rules"]],
  ["POST", "/v1/api-keys", J, ["name", "role", "expires_in_days"]],
  ["POST", "/v1/invitations", J, ["email", "role", "expires_in_hours"]],
  ["PATCH", `/v1/users/${UUID}`, J, ["role", "disabled"]],
  ["POST", "/v1/teams", J, ["name"]],
  ["PUT", "/v1/providers/openai/credential", J, ["api_key"]],
  ["PATCH", "/v1/providers/openai", J, ["enabled"]],
  ["POST", "/v1/invitations/accept", {}, ["token", "password"]],
  ["POST", "/v1/auth/login", {}, ["email", "password"]],
];

for (const [method, path, headers, fields] of targets) {
  for (const b of bodies(fields)) {
    judge(`${method} ${path} [${b.label}]`, await req(method, path, { ...b, headers }));
    await sleep(PACE_MS);
  }
}

// Paths, query strings and raw uploads.
const extra = [
  ["GET", `/v1/events/${MARK}`], ["GET", `/v1/events?limit=-5&before=${MARK}`], ["GET", `/v1/events?limit=999999`],
  ["GET", `/v1/usage?days=${MARK}`], ["GET", `/v1/policies/${"x".repeat(500)}`], ["GET", `/v1/events?risk_level=${MARK}`],
  ["DELETE", `/v1/api-keys/${MARK}`], ["DELETE", `/v1/teams/../../${MARK}`], ["GET", `/v1/%2e%2e/%2e%2e/${MARK}`],
];
for (const [m, p] of extra) { judge(`${m} ${p}`, await req(m, p, { headers: m === "GET" && p.startsWith("/v1/events") ? K : J })); await sleep(PACE_MS); }
for (const [label, raw, fname] of [["empty file", Buffer.alloc(0), "a.txt"], ["binary junk", Buffer.from(Array.from({ length: 4096 }, (_, i) => (i * 7919) % 256)), "a.pdf"],
  ["traversal filename", Buffer.from("hello " + MARK), `../../${MARK}.txt`], ["huge filename", Buffer.from("hi"), "a".repeat(5000) + ".txt"]]) {
  judge(`POST /v1/files/scan [${label}]`, await req("POST", "/v1/files/scan", { raw, ctype: "application/octet-stream", headers: { ...K, "x-filename": fname } }));
  await sleep(PACE_MS);
}
// Oversized body (bodyLimit is 2 MB): must be refused as 413, not accepted or crash.
judge("POST /v1/security/scan [3 MB body]", await req("POST", "/v1/security/scan", { body: { text: long(3_000_000) }, headers: K }));

// The gateway still works normally afterwards (nothing was corrupted, e.g. by prototype pollution).
const after = await req("POST", "/v1/security/check", { body: { text: "hello" }, headers: K });
const healthy = after.status === 200 && JSON.parse(after.text).allowed === true;
if (!healthy) { failures++; problems.push({ label: "gateway health after fuzzing", status: after.status, bad: ["unhealthy"], body: after.text.slice(0, 200) }); }

console.log(`requests: ${sent}  statuses: ${JSON.stringify(statuses)}`);
console.log(`gateway healthy after the campaign: ${healthy}`);
// Grouped: violation kind x endpoint, so one root cause does not hide another behind a truncated list.
const groups = new Map();
for (const p of problems) for (const b of p.bad) {
  const k = `${b} | ${p.label.replace(/ \[.*$/, "")}`;
  groups.set(k, [...(groups.get(k) ?? []), p]);
}
for (const [k, ps] of [...groups].sort()) console.log(`FAIL ${k}  x${ps.length}  e.g. [${ps[0].label.replace(/^.*? \[/, "[")}] -> ${ps[0].status} ${ps[0].body.slice(0, 140)}`);
for (const p of problems.filter((x) => x.status >= 500 || x.status <= 0)) console.log(`SERVER-SIDE ${p.label} -> ${p.status} :: ${p.body}`);
console.log(failures === 0 ? "FUZZ: ALL INVARIANTS HELD" : `FUZZ: ${failures} VIOLATION(S)`);
process.exit(failures === 0 ? 0 : 1);
