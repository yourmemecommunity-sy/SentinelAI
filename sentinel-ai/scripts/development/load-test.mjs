#!/usr/bin/env node
/**
 * Performance baseline for the SentinelAI gateway.
 *
 * Drives a running gateway with concurrent requests and reports RPS and latency percentiles per endpoint, plus a
 * multi-tenant run (several organizations at once). Measures the gateway as a client sees it: authentication, validation,
 * the security engine, policy, risk and audit are all in the path.
 *
 *   node scripts/development/load-test.mjs --url http://127.0.0.1:4000 --key snl_... [--seconds 10] [--concurrency 16]
 *
 * Keys for extra tenants may be passed as repeated --key flags; the multi-tenant phase uses all of them.
 */
const args = process.argv.slice(2);
const flag = (name, dflt) => { const i = args.indexOf(`--${name}`); return i === -1 ? dflt : args[i + 1]; };
const all = (name) => args.reduce((acc, a, i) => (a === `--${name}` ? [...acc, args[i + 1]] : acc), []);

const URL_BASE = flag("url", "http://127.0.0.1:4000").replace(/\/+$/, "");
const KEYS = all("key");
const SECONDS = Number(flag("seconds", 10));
const CONCURRENCY = Number(flag("concurrency", 16));
if (KEYS.length === 0) { console.error("at least one --key is required"); process.exit(2); }

const pct = (sorted, p) => sorted.length === 0 ? 0 : sorted[Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length))];

async function phase(name, keys, makeRequest) {
  const latencies = [];
  const codes = new Map();
  let inflight = 0, done = 0, errors = 0;
  const deadline = Date.now() + SECONDS * 1000;
  const started = Date.now();

  async function one(key) {
    const t0 = performance.now();
    try {
      const { path, body } = makeRequest();
      const res = await fetch(`${URL_BASE}${path}`, {
        method: "POST", headers: { "x-sentinel-api-key": key, "content-type": "application/json" }, body: JSON.stringify(body),
      });
      await res.text();
      codes.set(res.status, (codes.get(res.status) ?? 0) + 1);
    } catch { errors++; }
    latencies.push(performance.now() - t0);
    done++;
  }

  const workers = Array.from({ length: CONCURRENCY }, async (_, i) => {
    const key = keys[i % keys.length];
    while (Date.now() < deadline) { inflight++; await one(key); inflight--; }
  });
  await Promise.all(workers);

  const wall = (Date.now() - started) / 1000;
  latencies.sort((a, b) => a - b);
  return {
    name, requests: done, seconds: +wall.toFixed(1), rps: +(done / wall).toFixed(1), errors,
    p50: +pct(latencies, 50).toFixed(1), p95: +pct(latencies, 95).toFixed(1), p99: +pct(latencies, 99).toFixed(1),
    max: +(latencies.at(-1) ?? 0).toFixed(1),
    codes: Object.fromEntries([...codes].sort()),
  };
}

const CLEAN = "Summarize the key risks of adopting microservices in a large organization.";
const PII = "Please email jane.doe@example.com or call +1 415 555 0132 about invoice 5512.";
const SECRET = `deploy with ${"AK" + "IA" + "ABCDEFGHIJKLMNOP"}`;

const results = [];
results.push(await phase("scan: clean text", [KEYS[0]], () => ({ path: "/v1/security/scan", body: { text: CLEAN } })));
results.push(await phase("scan: PII (masked)", [KEYS[0]], () => ({ path: "/v1/security/scan", body: { text: PII } })));
results.push(await phase("scan: secret (blocked)", [KEYS[0]], () => ({ path: "/v1/security/scan", body: { text: SECRET } })));
results.push(await phase("check: allow/deny", [KEYS[0]], () => ({ path: "/v1/security/check", body: { text: CLEAN } })));
if (KEYS.length > 1) {
  results.push(await phase(`multi-tenant scan (${KEYS.length} orgs)`, KEYS, () => ({ path: "/v1/security/scan", body: { text: Math.random() < 0.5 ? PII : CLEAN } })));
}

console.log(`\nSentinelAI load baseline — ${SECONDS}s per phase, concurrency ${CONCURRENCY}, ${new Date().toISOString()}`);
console.log(`target: ${URL_BASE}\n`);
console.log("| phase | requests | RPS | p50 ms | p95 ms | p99 ms | max ms | errors | statuses |");
console.log("|---|---|---|---|---|---|---|---|---|");
for (const r of results) {
  console.log(`| ${r.name} | ${r.requests} | ${r.rps} | ${r.p50} | ${r.p95} | ${r.p99} | ${r.max} | ${r.errors} | ${JSON.stringify(r.codes)} |`);
}
console.log();
