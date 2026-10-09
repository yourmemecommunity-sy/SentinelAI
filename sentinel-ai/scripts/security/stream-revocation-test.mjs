// Mid-stream API-key revocation test (run by scripts/security/run-stream-revocation-test.sh inside the compose network).
//
// Each TRIAL opens /v1/ai/stream with its own fresh API key against a slow mock provider (one word every MOCK_TOKEN_MS),
// waits REVOKE_AFTER_MS after the first delta, revokes the key through DELETE /v1/api-keys/:id (a user session), and keeps
// reading. Meanwhile BG_STREAMS background streams on other keys run continuously (the "concurrent load"); their timings
// are the latency baseline. Every second trial asks for a reply that contains a fake credential-shaped value late in the
// stream (LEAKTEST), so the output checks have something to stop.
//
// Measured per trial, with "after revocation" = after the revoke call returned 204:
//   words_after_revoke_live   words that reached the client in ordinary deltas after revocation (the leak)
//   words_after_revoke_release words released at the end after a quarantine scan (after-change only)
//   last_live_delta_ms        how long after revocation the last ordinary delta arrived (time to stop)
//   end_ms                    how long after revocation the stream ended, and with which final event
//   fake_key_reached_client   whether the credential-shaped value was ever delivered
//   key_rejected_after        whether a new request with the revoked key is refused (401)
// No content is stored: only counts, timings and event names. Usage: node stream-revocation-test.mjs > report.json
const API = process.env.API || "http://api:4000";
const LABEL = process.env.LABEL || "run";
const TRIALS = Number(process.env.TRIALS || 24);
const PARALLEL = Number(process.env.PARALLEL || 4);
const BG_STREAMS = Number(process.env.BG_STREAMS || 16);
const REVOKE_AFTER_MS = Number(process.env.REVOKE_AFTER_MS || 1500);

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const now = () => performance.now();
const pct = (xs, p) => { if (!xs.length) return null; const s = [...xs].sort((a, b) => a - b); return Math.round(s[Math.min(s.length - 1, Math.floor(p / 100 * s.length))]); };
const stats = (xs) => ({ n: xs.length, p50: pct(xs, 50), p95: pct(xs, 95), p99: pct(xs, 99), max: xs.length ? Math.round(Math.max(...xs)) : null });
const words = (t) => (t.match(/\bw\d+\b/g) || []).length;

async function json(method, path, body, auth) {
  const r = await fetch(`${API}${path}`, { method, headers: { ...(body ? { "content-type": "application/json" } : {}), ...(auth ? { authorization: `Bearer ${auth}` } : {}) },
    ...(body ? { body: JSON.stringify(body) } : {}) });
  const text = await r.text();
  return { status: r.status, body: text ? JSON.parse(text) : null };
}

/** Opens a stream and calls onEvent(name, data, t) for every SSE event; resolves when the stream ends. */
async function stream(key, content, onEvent, signal) {
  const t0 = now();
  const r = await fetch(`${API}/v1/ai/stream`, { method: "POST", signal,
    headers: { "content-type": "application/json", authorization: `Bearer ${key}` },
    body: JSON.stringify({ provider: "ollama", messages: [{ role: "user", content }] }) });
  if (r.status !== 200) { onEvent("http_error", { status: r.status }, now()); return { t0, status: r.status }; }
  const reader = r.body.getReader();
  const dec = new TextDecoder();
  let buf = "";
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    buf += dec.decode(value, { stream: true });
    let i;
    while ((i = buf.indexOf("\n\n")) >= 0) {
      const frame = buf.slice(0, i); buf = buf.slice(i + 2);
      const ev = /^event: (.*)$/m.exec(frame)?.[1];
      const data = /^data: (.*)$/m.exec(frame)?.[1];
      if (ev) onEvent(ev, data ? JSON.parse(data) : null, now());
    }
  }
  return { t0, status: 200 };
}

async function main() {
  const slug = `revocation-${LABEL}-${Date.now()}`;
  const s = await json("POST", "/v1/auth/signup", { organization_name: slug, email: `${slug}@example.com`, password: "Revocation-Test-Passw0rd!" });
  if (s.status !== 201) throw new Error(`signup ${s.status}`);
  const user = s.body.access_token;
  const newKey = async (name) => {
    const k = await json("POST", "/v1/api-keys", { name, role: "DEVELOPER", expires_in_days: 1 }, user);
    if (k.status !== 201) throw new Error(`api key ${k.status}`);
    return { id: k.body.id, key: k.body.key };
  };

  // ---- background load: BG_STREAMS concurrent streams on keys that are never revoked (max 8 streams per key)
  const bgKeys = await Promise.all(Array.from({ length: Math.ceil(BG_STREAMS / 8) }, (_, i) => newKey(`bg-${i}`)));
  let stopBg = false;
  const bg = { first_delta_ms: [], total_ms: [], finals: {} };
  const bgWorker = async (i) => {
    while (!stopBg) {
      let first = null; let final = "none";
      const r = await stream(bgKeys[i % bgKeys.length].key, "please continue", (ev, data, t) => {
        if (ev === "delta" && first === null) first = t;
        if (ev === "done") final = "done";
        if (ev === "error") final = `error:${data?.error}`;
        if (ev === "http_error") final = `http_${data.status}`;
      }).catch(() => ({ t0: now(), status: 0 }));
      if (r.status === 200 && first !== null) bg.first_delta_ms.push(first - r.t0);
      bg.total_ms.push(now() - r.t0);
      bg.finals[final] = (bg.finals[final] ?? 0) + 1;
      if (r.status !== 200) await sleep(200);
    }
  };
  const bgDone = Array.from({ length: BG_STREAMS }, (_, i) => bgWorker(i));
  await sleep(2000); // let the load ramp up

  // ---- trials
  const trials = [];
  const runTrial = async (n) => {
    const leak = n % 2 === 1;
    const k = await newKey(`trial-${n}`);
    const deltas = []; // [t, words, chars, containsFakeKey]
    let final = null; let revokeSent = null; let revokeAck = null; let firstDelta = null;
    const revoke = async () => {
      revokeSent = now();
      const r = await json("DELETE", `/v1/api-keys/${k.id}`, null, user);
      revokeAck = now();
      if (r.status !== 204) throw new Error(`revoke ${r.status}`);
    };
    let revoking = null;
    const r = await stream(k.key, leak ? "LEAKTEST please continue" : "please continue", (ev, data, t) => {
      if (ev === "delta") {
        deltas.push([t, words(data.text), data.text.length, /AKIA[A-Z0-9]{16}/.test(data.text)]);
        if (firstDelta === null) { firstDelta = t; revoking = sleep(REVOKE_AFTER_MS).then(revoke); }
      } else if (ev === "done") final = { event: "done" };
      else if (ev === "error") final = { event: "error", error: data?.error, ...(data?.outcome ? { outcome: data.outcome } : {}), ...(data?.reason ? { reason: data.reason } : {}) };
      else if (ev === "http_error") final = { event: `http_${data.status}` };
    });
    const end = now();
    if (revoking) await revoking;
    const released = final?.outcome === "released" ? deltas.at(-1) : null;   // the quarantine release is the last delta
    const live = deltas.filter((d) => d !== released && revokeAck !== null && d[0] > revokeAck);
    const after = await fetch(`${API}/v1/ai/stream`, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${k.key}` },
      body: JSON.stringify({ provider: "ollama", messages: [{ role: "user", content: "hello" }] }) });
    await after.body?.cancel();
    trials.push({
      trial: n, leak_prompt: leak, status: r.status, final,
      revoke_call_ms: revokeAck && revokeSent ? Math.round(revokeAck - revokeSent) : null,
      words_before_revoke: deltas.filter((d) => revokeAck === null || d[0] <= revokeAck).reduce((a, d) => a + d[1], 0),
      words_after_revoke_live: live.reduce((a, d) => a + d[1], 0),
      chars_after_revoke_live: live.reduce((a, d) => a + d[2], 0),
      words_after_revoke_release: released ? released[1] : 0,
      last_live_delta_ms: live.length ? Math.round(live.at(-1)[0] - revokeAck) : 0,
      end_ms: revokeAck ? Math.round(end - revokeAck) : null,
      fake_key_reached_client: deltas.some((d) => d[3]),
      key_rejected_after: after.status === 401,
    });
  };
  for (let i = 0; i < TRIALS; i += PARALLEL) {
    await Promise.all(Array.from({ length: Math.min(PARALLEL, TRIALS - i) }, (_, j) => runTrial(i + j)));
  }
  stopBg = true;
  await Promise.all(bgDone);

  const sum = (f) => trials.reduce((a, t) => a + f(t), 0);
  const finals = {};
  for (const t of trials) { const k = t.final ? [t.final.event, t.final.error, t.final.outcome].filter(Boolean).join(":") : "none"; finals[k] = (finals[k] ?? 0) + 1; }
  console.log(JSON.stringify({
    label: LABEL, generated_at: new Date().toISOString(),
    config: { TRIALS, PARALLEL, BG_STREAMS, REVOKE_AFTER_MS, mock_tokens: Number(process.env.MOCK_STREAM_TOKENS || 0), mock_token_ms: Number(process.env.MOCK_TOKEN_MS || 0) },
    summary: {
      trials: trials.length,
      streams_continuing_after_revoke: trials.filter((t) => t.words_after_revoke_live > 0).length,
      words_after_revoke_live: { total: sum((t) => t.words_after_revoke_live), ...stats(trials.map((t) => t.words_after_revoke_live)) },
      chars_after_revoke_live_total: sum((t) => t.chars_after_revoke_live),
      last_live_delta_ms: stats(trials.map((t) => t.last_live_delta_ms)),
      end_ms: stats(trials.map((t) => t.end_ms).filter((x) => x !== null)),
      words_released_after_quarantine_scan: sum((t) => t.words_after_revoke_release),
      final_events: finals,
      fake_key_reached_client: trials.filter((t) => t.fake_key_reached_client).length,
      key_rejected_after_revoke: trials.filter((t) => t.key_rejected_after).length,
      revoke_call_ms: stats(trials.map((t) => t.revoke_call_ms).filter((x) => x !== null)),
      background: { streams: bg.total_ms.length, first_delta_ms: stats(bg.first_delta_ms), total_ms: stats(bg.total_ms), finals: bg.finals },
    },
    trials,
  }, null, 2));
}

main().catch((e) => { console.error(String(e)); process.exit(1); });
