// A stand-in for an Ollama server that answers instantly, so a benchmark measures only what the gateway and the security
// engine cost. Implements the two endpoints the gateway's Ollama adapter uses: POST /api/chat (non-streaming and NDJSON
// streaming) and GET /api/tags. No dependencies:  node mock-ollama.mjs [port]
//
// Slow streaming (used by the mid-stream revocation test): MOCK_STREAM_TOKENS=N MOCK_TOKEN_MS=ms streams N numbered words
// ("w0 w1 ...") one every ms milliseconds. If the prompt contains LEAKTEST, a fake credential-shaped value is emitted at 70 %
// of the stream, so the output checks have something to block late in the reply. The value is assembled at runtime (no
// secret-shaped literal in source) and is not a real credential.
import { createServer } from "node:http";

const port = Number(process.argv[2] ?? 11434);
const REPLY = "OK, noted.";
const SLOW_TOKENS = Number(process.env.MOCK_STREAM_TOKENS ?? 0);
const TOKEN_MS = Number(process.env.MOCK_TOKEN_MS ?? 25);
const FAKE_KEY = "AK" + "IA" + "QWERTYUIOPASDFGH";

function slowStream(res, model, leak) {
  res.writeHead(200, { "content-type": "application/x-ndjson" });
  let i = 0;
  const leakAt = Math.floor(SLOW_TOKENS * 0.7);
  const timer = setInterval(() => {
    if (res.destroyed) return clearInterval(timer);
    if (i >= SLOW_TOKENS) {
      clearInterval(timer);
      return res.end(JSON.stringify({ model, message: { role: "assistant", content: "" }, done: true, done_reason: "stop", prompt_eval_count: 12, eval_count: SLOW_TOKENS }) + "\n");
    }
    const word = leak && i === leakAt ? `key ${FAKE_KEY} ` : `w${i} `;
    res.write(JSON.stringify({ model, message: { role: "assistant", content: word }, done: false }) + "\n");
    i += 1;
  }, TOKEN_MS);
  res.on("close", () => clearInterval(timer));   // the gateway aborted the upstream request
}

createServer((req, res) => {
  const chunks = [];
  req.on("data", (c) => chunks.push(c));
  req.on("end", () => {
    if (req.method === "GET" && req.url === "/api/tags") {
      res.writeHead(200, { "content-type": "application/json" });
      return res.end(JSON.stringify({ models: [{ name: "mock" }] }));
    }
    if (req.method === "POST" && req.url === "/api/chat") {
      let body = {};
      try { body = JSON.parse(Buffer.concat(chunks).toString() || "{}"); } catch { /* answer anyway */ }
      const model = body.model ?? "mock";
      if (body.stream && SLOW_TOKENS > 0) {
        return slowStream(res, model, JSON.stringify(body.messages ?? []).includes("LEAKTEST"));
      }
      if (body.stream) {
        res.writeHead(200, { "content-type": "application/x-ndjson" });
        res.write(JSON.stringify({ model, message: { role: "assistant", content: REPLY }, done: false }) + "\n");
        return res.end(JSON.stringify({ model, message: { role: "assistant", content: "" }, done: true, done_reason: "stop", prompt_eval_count: 12, eval_count: 3 }) + "\n");
      }
      res.writeHead(200, { "content-type": "application/json" });
      return res.end(JSON.stringify({ model, message: { role: "assistant", content: REPLY }, done: true, done_reason: "stop", prompt_eval_count: 12, eval_count: 3 }));
    }
    res.writeHead(404); res.end();
  });
}).listen(port, "0.0.0.0", () => console.log(`mock ollama on :${port}${SLOW_TOKENS ? ` (slow: ${SLOW_TOKENS} tokens every ${TOKEN_MS} ms)` : ""}`));
