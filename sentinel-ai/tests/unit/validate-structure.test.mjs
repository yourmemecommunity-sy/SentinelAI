import { test } from "node:test";
import assert from "node:assert/strict";
import { copyFileSync, mkdtempSync, writeFileSync, mkdirSync, readdirSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { validate } from "../../scripts/development/validate-structure.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const SKIP = new Set(["node_modules", ".git", ".venv", "__pycache__", ".pytest_cache", "dist", ".next"]);

// Explicit copier: skips dependency/build dirs entirely (pnpm node_modules is full of symlinks fs.cpSync cannot recreate).
function copyTree(src, dst) {
  mkdirSync(dst, { recursive: true });
  for (const name of readdirSync(src)) {
    if (SKIP.has(name)) continue;
    const from = join(src, name);
    const to = join(dst, name);
    if (statSync(from).isDirectory()) copyTree(from, to);
    else copyFileSync(from, to);
  }
}

function cloneRepo() {
  const dir = mkdtempSync(join(tmpdir(), "sentinel-structure-"));
  copyTree(repoRoot, dir);
  return dir;
}
// Fixture secrets are assembled at runtime so this file itself never contains a secret-shaped literal.
const FAKE_AWS_KEY = "AK" + "IA" + "ABCDEFGHIJKLMNOP";

test("the real repository is valid", () => {
  assert.deepEqual(validate(repoRoot), []);
});

test("an empty directory fails with missing-structure violations", () => {
  const dir = mkdtempSync(join(tmpdir(), "sentinel-empty-"));
  try {
    const v = validate(dir);
    assert.ok(v.includes("missing required directory: apps/api/src"));
    assert.ok(v.includes("missing required file: README.md"));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("detects forbidden root files, misplaced tests/datasets/docs, bad names and committed secrets", () => {
  const dir = cloneRepo();
  try {
    writeFileSync(join(dir, "temp.py"), "print(1)\n");
    mkdirSync(join(dir, "apps/api/src/utils"), { recursive: true });
    writeFileSync(join(dir, "apps/api/src/utils/final.ts"), "export {}\n");
    writeFileSync(join(dir, "apps/api/src/utils/helper.test.ts"), "export {}\n");
    writeFileSync(join(dir, "apps/api/src/cases.jsonl"), "{}\n");
    writeFileSync(join(dir, "apps/api/src/NOTES.md"), "x\n");
    writeFileSync(join(dir, "apps/api/src/config/leak.ts"), `export const k = "${FAKE_AWS_KEY}";\n`);
    writeFileSync(join(dir, ".env"), "X=1\n");
    const v = validate(dir).join("\n");
    for (const expected of [
      "forbidden file in repo root: temp.py",
      "meaningless file name: apps/api/src/utils/final.ts",
      "test file outside a tests/ directory: apps/api/src/utils/helper.test.ts",
      "dataset file outside datasets/: apps/api/src/cases.jsonl",
      "documentation outside docs/: apps/api/src/NOTES.md",
      "possible committed secret (AWS access key id): apps/api/src/config/leak.ts",
      "forbidden file in repo root: .env",
    ]) assert.ok(v.includes(expected), `expected violation: ${expected}\n---\n${v}`);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
