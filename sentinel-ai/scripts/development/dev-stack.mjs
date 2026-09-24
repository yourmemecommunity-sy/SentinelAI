#!/usr/bin/env node
// Starts the whole product locally without Docker or a database server:
//   security engine + document scanner + token vault (Python)  ->  gateway (in-memory Postgres via PGlite)  ->  dashboard (Next.js)
// Ctrl+C stops everything. Development only: data lives in memory and dev secrets are baked in.
//
//   node scripts/development/dev-stack.mjs            (dashboard in dev mode)
//   node scripts/development/dev-stack.mjs --prod     (dashboard built + started; needs `pnpm build` first)
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const isWin = process.platform === "win32";
const venvPy = resolve(ROOT, "services/security-engine", isWin ? ".venv/Scripts/python.exe" : ".venv/bin/python");
const python = process.env.SENTINEL_PYTHON ?? (existsSync(venvPy) ? venvPy : "python");
const prod = process.argv.includes("--prod");
const npx = isWin ? "npx.cmd" : "npx";

const children = [];
function run(name, cmd, args, cwd, env = {}) {
  const p = spawn(cmd, args, { cwd, env: { ...process.env, ...env }, shell: isWin && cmd === npx, stdio: ["ignore", "pipe", "pipe"] });
  const tag = (s) => String(s).split(/\r?\n/).filter(Boolean).forEach((l) => console.log(`[${name}] ${l}`));
  p.stdout.on("data", tag); p.stderr.on("data", tag);
  p.on("exit", (code) => { console.log(`[${name}] exited (${code})`); shutdown(code ?? 1); });
  children.push(p);
}
let stopping = false;
function shutdown(code = 0) {
  if (stopping) return;
  stopping = true;
  for (const c of children) try { c.kill(); } catch { /* already gone */ }
  setTimeout(() => process.exit(code), 300);
}
process.on("SIGINT", () => shutdown(0));
process.on("SIGTERM", () => shutdown(0));

run("token-vault", python, ["-m", "uvicorn", "app.main:app", "--port", "8004", "--log-level", "warning"], resolve(ROOT, "services/token-vault"),
  { SENTINEL_ENV: "development", VAULT_BACKEND: "memory", VAULT_TOKEN: "dev-only-vault-token-1234" });
run("engine", python, ["-m", "uvicorn", "app.main:app", "--port", "8001", "--log-level", "warning"], resolve(ROOT, "services/security-engine"),
  { VAULT_URL: "http://127.0.0.1:8004", VAULT_TOKEN: "dev-only-vault-token-1234" });
run("document-scanner", python, ["-m", "uvicorn", "app.main:app", "--port", "8003", "--log-level", "warning"], resolve(ROOT, "services/document-scanner"),
  { SENTINEL_ENV: "development", MALWARE_SCANNER: "eicar" });
run("gateway", npx, ["tsx", "dev/devServer.ts"], resolve(ROOT, "apps/api"), { SECURITY_ENGINE_URL: "http://127.0.0.1:8001", DOCUMENT_SCANNER_URL: "http://127.0.0.1:8003",
  VAULT_URL: "http://127.0.0.1:8004", VAULT_TOKEN: "dev-only-vault-token-1234" });
run("dashboard", npx, prod ? ["next", "start", "-p", "3000"] : ["next", "dev", "-p", "3000"], resolve(ROOT, "apps/dashboard"),
  { GATEWAY_URL: "http://127.0.0.1:4000", NEXT_TELEMETRY_DISABLED: "1" });
console.log("[stack] starting... dashboard: http://localhost:3000 (register an organization on the sign-up page)");
