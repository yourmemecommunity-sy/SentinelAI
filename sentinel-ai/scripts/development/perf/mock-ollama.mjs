// A stand-in for an Ollama server that answers instantly, so a benchmark measures only what the gateway and the security
// engine cost. Implements the two endpoints the gateway's Ollama adapter uses: POST /api/chat (non-streaming and NDJSON
// streaming) and GET /api/tags. No dependencies:  node mock-ollama.mjs [port]
import { createServer } from "node:http";

const port = Number(process.argv[2] ?? 11434);
const REPLY = "OK, noted.";

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
}).listen(port, "0.0.0.0", () => console.log(`mock ollama on :${port}`));
