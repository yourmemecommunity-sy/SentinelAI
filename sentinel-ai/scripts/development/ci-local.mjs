#!/usr/bin/env node
/**
 * Runs the full SentinelAI verification gate locally, in the same order CI does, and prints a pass/fail table.
 *
 *   node scripts/development/ci-local.mjs                 # everything available on this machine
 *   node scripts/development/ci-local.mjs --quick         # skip the slowest suites
 *
 * Steps whose dependency is missing are reported as SKIPPED with the reason, never as passed. The exit code is non-zero
 * if any step failed; skipped steps do not fail the gate but are always listed.
 *
 * Optional environment:
 *   SENTINEL_TEST_DATABASE_URL   run the database suites against a real PostgreSQL server
 *   VAULT_TEST_REDIS_URL         run the token-vault suite against a real Redis server
 */
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const QUICK = process.argv.includes("--quick");
const isWin = process.platform === "win32";
const PY = process.env.SENTINEL_PYTHON ?? resolve(ROOT, "services/security-engine", isWin ? ".venv/Scripts/python.exe" : ".venv/bin/python");
const PNPM = isWin ? "npx.cmd" : "npx";
const pnpmArgs = (...a) => ["pnpm@9", ...a];

const steps = [];
const step = (name, opts) => steps.push({ name, ...opts });

// 1. static checks
step("structure validator", { cmd: process.execPath, args: ["scripts/development/validate-structure.mjs"] });
step("structure validator tests", { cmd: process.execPath, args: ["--test", "tests/unit/validate-structure.test.mjs"] });
step("typecheck + build (all workspaces)", { cmd: PNPM, args: pnpmArgs("build"), slow: true });

// 2. unit / integration
step("workspace tests (api, dashboard, router, sdk-js)", { cmd: PNPM, args: pnpmArgs("test"), slow: true });
step("security engine", { cmd: PY, args: ["-m", "pytest", "-q", "-p", "no:cacheprovider"], cwd: "services/security-engine", need: PY });
step("token vault", { cmd: PY, args: ["-m", "pytest", "-q", "-p", "no:cacheprovider"], cwd: "services/token-vault", need: PY });
step("document scanner", { cmd: PY, args: ["-m", "pytest", "-q", "-p", "no:cacheprovider"], cwd: "services/document-scanner", need: PY });
step("python SDK", { cmd: PY, args: ["-m", "pytest", "packages/sdk/python/tests", "-q", "-p", "no:cacheprovider"], need: PY });

// 3. security gates
step("security + regression suites", { cmd: PY, args: ["-m", "pytest", "tests/security", "tests/regression", "-q", "-p", "no:cacheprovider"], need: PY });
step("evaluation gate (critical regressions fail)", { cmd: PY, args: ["scripts/security/run_evaluation.py"], need: PY });
step("node dependency audit", { cmd: PNPM, args: pnpmArgs("audit", "--prod", "--audit-level=high") });

// 4. real-infrastructure suites (only when pointed at real servers)
step("database suites on REAL PostgreSQL", {
  cmd: PNPM, args: pnpmArgs("--filter", "@sentinelai/api", "exec", "vitest", "run", "tests/db"),
  need: process.env.SENTINEL_TEST_DATABASE_URL, needText: "SENTINEL_TEST_DATABASE_URL is not set", slow: true,
});
step("token vault on REAL Redis", {
  cmd: PY, args: ["-m", "pytest", "-q", "-p", "no:cacheprovider"], cwd: "services/token-vault",
  need: process.env.VAULT_TEST_REDIS_URL && PY, needText: "VAULT_TEST_REDIS_URL is not set",
});

const results = [];
for (const s of steps) {
  if (QUICK && s.slow) { results.push({ ...s, status: "SKIPPED", detail: "--quick" }); continue; }
  // Only a step that DECLARES a dependency can be skipped; a step with no `need` always runs. (An earlier version treated
  // "no dependency declared" as "dependency missing" and silently skipped the most important steps.)
  const declared = Object.prototype.hasOwnProperty.call(s, "need");
  const missing = declared && (!s.need || (typeof s.need === "string" && s.need.includes("python") && !existsSync(s.need)));
  if (missing) {
    results.push({ ...s, status: "SKIPPED", detail: s.needText ?? "dependency missing" });
    continue;
  }
  const t0 = Date.now();
  process.stdout.write(`\n=== ${s.name}\n`);
  const r = spawnSync(s.cmd, s.args, { cwd: resolve(ROOT, s.cwd ?? "."), stdio: "inherit", shell: isWin && s.cmd === PNPM, env: process.env });
  results.push({ ...s, status: r.status === 0 ? "PASS" : "FAIL", detail: `${((Date.now() - t0) / 1000).toFixed(0)}s`, code: r.status });
}

const pad = (s, n) => String(s).padEnd(n);
console.log(`\n${"=".repeat(78)}\nSentinelAI local verification gate — ${new Date().toISOString()}\n${"=".repeat(78)}`);
for (const r of results) console.log(`${pad(r.status, 8)} ${pad(r.name, 52)} ${r.detail ?? ""}`);
const failed = results.filter((r) => r.status === "FAIL");
const skipped = results.filter((r) => r.status === "SKIPPED");
console.log(`\n${results.filter((r) => r.status === "PASS").length} passed, ${failed.length} failed, ${skipped.length} skipped`);
if (skipped.length) console.log(`skipped: ${skipped.map((s) => `${s.name} (${s.detail})`).join("; ")}`);
process.exit(failed.length === 0 ? 0 : 1);
