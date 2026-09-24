// k6 load script for the gateway (run by scripts/development/perf-bench.sh; k6 runs in the grafana/k6 container).
//
//   TARGET=direct     POST mock-ollama /api/chat directly         (the provider hop alone: what a client would pay anyway)
//   TARGET=chat       POST gateway /v1/ai/chat, clean prompt       (auth + input scan + policy + provider + output scan + audit)
//   TARGET=chat_pii   POST gateway /v1/ai/chat, prompt with email  (same, with the MASK path)
//   TARGET=scan       POST gateway /v1/security/scan               (auth + engine scan + audit, no provider)
//
// Env: TARGET, VUS, DURATION, API (gateway base), MOCK (mock base). A throwaway organization + API key are created in setup().
import http from "k6/http";
import { check } from "k6";

const API = __ENV.API || "http://api:4000";
const MOCK = __ENV.MOCK || "http://mock-ollama:11434";
const TARGET = __ENV.TARGET || "chat";

export const options = {
  vus: Number(__ENV.VUS || 8),
  duration: __ENV.DURATION || "30s",
  summaryTrendStats: ["min", "med", "avg", "p(90)", "p(95)", "p(99)", "max"],
  thresholds: { checks: ["rate>0.999"] }, // any wrong status fails the run: the numbers are only valid if every call succeeded
};

export function setup() {
  if (TARGET === "direct") return { key: "" };
  const slug = `perf-${Date.now()}`;
  const s = http.post(`${API}/v1/auth/signup`, JSON.stringify({ organization_name: slug, email: `${slug}@example.com`, password: "Perf-Bench-Passw0rd!" }),
    { headers: { "content-type": "application/json" } });
  if (s.status !== 201) throw new Error(`signup ${s.status}`);
  const k = http.post(`${API}/v1/api-keys`, JSON.stringify({ name: "perf", role: "DEVELOPER" }),
    { headers: { "content-type": "application/json", authorization: `Bearer ${s.json("access_token")}` } });
  if (k.status !== 201) throw new Error(`api key ${k.status}`);
  return { key: k.json("key") };
}

// Every non-OK response is printed (status + machine-readable reason, never content), up to 20 per VU, so a failure
// under load can be diagnosed: a fail-closed refusal (403/503 with a reason) and a crash (500) mean different things.
let logged = 0;
function report(res) {
  if (logged >= 20) return;
  logged += 1;
  let why = "";
  try { const b = res.json(); why = `${b.error ?? ""} ${b.reason ?? b.fail_closed_reason ?? ""} failed_closed=${b.failed_closed ?? b.security?.input?.failed_closed ?? ""}`; } catch { why = String(res.body).slice(0, 80); }
  console.warn(`NOT-OK target=${TARGET} vu=${__VU} status=${res.status} ${why} duration_ms=${res.timings.duration.toFixed(0)}`);
}

export default function (data) {
  const h = { headers: { "content-type": "application/json", "x-sentinel-api-key": data.key } };
  let res;
  if (TARGET === "direct") {
    res = http.post(`${MOCK}/api/chat`, JSON.stringify({ model: "mock", stream: false, messages: [{ role: "user", content: "Summarise the quarterly plan in one line." }] }), h);
    if (!check(res, { "200": (r) => r.status === 200 })) report(res);
  } else if (TARGET === "scan") {
    res = http.post(`${API}/v1/security/scan`, JSON.stringify({ text: "Please summarise the quarterly plan in one line for the team." }), h);
    if (!check(res, { "200 + decision": (r) => r.status === 200 && r.json("decision") === "ALLOW" })) report(res);
  } else {
    const content = TARGET === "chat_pii" ? "Please email jane.doe@example.com a one-line summary of the quarterly plan." : "Summarise the quarterly plan in one line.";
    res = http.post(`${API}/v1/ai/chat`, JSON.stringify({ provider: "ollama", messages: [{ role: "user", content }] }), h);
    const want = TARGET === "chat_pii" ? "MASK" : "ALLOW";
    if (!check(res, { "200 + verdict": (r) => r.status === 200 && r.json("security.input.decision") === want && r.json("content") === "OK, noted." })) report(res);
  }
}
