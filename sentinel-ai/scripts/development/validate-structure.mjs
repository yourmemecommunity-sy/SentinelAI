#!/usr/bin/env node
// SentinelAI repository structure validator. Zero dependencies; CI runs this and fails on any violation.
// Usage: node scripts/development/validate-structure.mjs [rootDir]
import { readdirSync, readFileSync, statSync, existsSync } from "node:fs";
import { join, relative, basename, sep, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const REQUIRED_DIRS = [
  "apps/dashboard/app", "apps/dashboard/components", "apps/dashboard/lib", "apps/dashboard/hooks",
  "apps/dashboard/types", "apps/dashboard/public", "apps/dashboard/styles", "apps/dashboard/tests",
  "apps/api/src", "apps/api/tests",
  "services/security-engine/app", "services/security-engine/tests",
  "services/document-scanner/app", "services/document-scanner/tests",
  "services/token-vault/app", "services/token-vault/tests",
  "services/ai-router/src", "services/ai-router/tests",
  "services/policy-engine/app", "services/policy-engine/tests",
  "packages/shared-types/src", "packages/sdk/javascript/src", "packages/sdk/python/sentinelai",
  "packages/security-rules",
  "datasets/pii", "datasets/financial", "datasets/secrets", "datasets/prompt-injection", "datasets/jailbreak",
  "datasets/data-exfiltration", "datasets/malicious-documents", "datasets/output-leakage", "datasets/evaluation",
  "tests/unit", "tests/integration", "tests/security", "tests/e2e", "tests/regression",
  "infrastructure/docker", "infrastructure/kubernetes", "infrastructure/helm", "infrastructure/terraform",
  "docs/architecture", "docs/api", "docs/security", "docs/database", "docs/deployment", "docs/sdk", "docs/evaluation",
  "scripts/development", "scripts/database", "scripts/dataset", "scripts/security", "scripts/deployment",
  ".github/workflows",
];

const REQUIRED_FILES = [
  ".env.example", ".gitignore", "docker-compose.yml", "package.json", "pnpm-workspace.yaml",
  "tsconfig.base.json", "README.md", "LICENSE", "SECURITY.md",
  "scripts/development/validate-structure.mjs",
];

// Root allow-list. pnpm-lock.yaml is a generated lockfile that pnpm requires at the workspace root; .gitleaks.toml is the
// secret-scanner configuration, which the scanner only reads from the repository root.
const ROOT_ALLOWED_FILES = new Set([
  "README.md", "LICENSE", "SECURITY.md", ".env.example", ".gitignore", ".gitattributes", ".gitleaks.toml", "docker-compose.yml",
  "package.json", "pnpm-workspace.yaml", "tsconfig.base.json", "pnpm-lock.yaml",
]);
const ROOT_ALLOWED_DIRS = new Set([
  "apps", "services", "packages", "datasets", "tests", "infrastructure", "docs", "scripts", ".github",
  "node_modules", ".git",
]);

const PYTHON_SERVICES = ["security-engine", "document-scanner", "policy-engine", "token-vault"];
const TS_PROJECTS = ["apps/api", "services/ai-router", "packages/shared-types"];

const SKIP_DIRS = new Set(["node_modules", ".git", ".venv", "venv", "__pycache__", ".next", "dist", "coverage",
  ".pytest_cache", ".mypy_cache", ".ruff_cache", ".terraform"]);

const BAD_NAME = /^(test\d*|new|final|temp|tmp|working|abc|untitled|copy)\.(js|mjs|ts|tsx|py)$/i;
const TEST_FILE = /(\.test\.(ts|tsx|js|mjs)|\.spec\.(ts|tsx|js|mjs)|^test_.*\.py|_test\.py)$/;
const DATASET_FILE = /\.(jsonl|ndjson|parquet)$/i;

// Paths exempt from the secret scan. Deliberately empty: the evaluation datasets store secret-shaped values defanged
// (scripts/dataset/defang.py) and tests assemble them at runtime, so nothing in the repository needs an exception.
const SECRET_SCAN_EXEMPT = [];
const SECRET_PATTERNS = [
  ["private key block", /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----/],
  ["AWS access key id", /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/],
  ["GitHub token", /\bgh[pousr]_[A-Za-z0-9]{36,}\b/],
  ["Google API key", /\bAIza[0-9A-Za-z_-]{35}\b/],
  ["Slack token", /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/],
  ["Anthropic/OpenAI-style key", /\bsk-(?:ant-)?[A-Za-z0-9_-]{32,}\b/],
];
const SECRET_SCAN_MAX_BYTES = 1_000_000;

/** @returns {string[]} violations (empty when the repo is valid) */
export function validate(root) {
  const v = [];
  const rel = (p) => relative(root, p).split(sep).join("/");
  const isDir = (p) => existsSync(p) && statSync(p).isDirectory();

  for (const d of REQUIRED_DIRS) if (!isDir(join(root, d))) v.push(`missing required directory: ${d}`);
  for (const f of REQUIRED_FILES) if (!existsSync(join(root, f))) v.push(`missing required file: ${f}`);

  // Root allow-list
  for (const name of readdirSync(root)) {
    const full = join(root, name);
    if (statSync(full).isDirectory()) {
      // Local build/tool caches (all git-ignored) are not part of the repository's structure: running pytest or ruff
      // from the root must not make the structure invalid.
      if (SKIP_DIRS.has(name)) continue;
      if (!ROOT_ALLOWED_DIRS.has(name)) v.push(`unexpected directory in repo root: ${name}/`);
    } else if (!ROOT_ALLOWED_FILES.has(name)) {
      v.push(`forbidden file in repo root: ${name}`);
    }
  }

  // Service project configuration
  for (const s of PYTHON_SERVICES) {
    const base = join(root, "services", s);
    for (const f of ["pyproject.toml", "requirements.txt", "Dockerfile", "README.md"]) {
      if (!existsSync(join(base, f))) v.push(`services/${s} missing ${f}`);
    }
    const py = join(base, "pyproject.toml");
    if (existsSync(py)) {
      const t = readFileSync(py, "utf8");
      if (!/^\[project\]/m.test(t) || !/^name\s*=/m.test(t)) v.push(`services/${s}/pyproject.toml lacks [project] name`);
    }
  }
  for (const p of TS_PROJECTS) {
    const base = join(root, p);
    for (const f of ["package.json", "tsconfig.json"]) {
      if (!existsSync(join(base, f))) v.push(`${p} missing ${f}`);
    }
    const pj = join(base, "package.json");
    if (existsSync(pj)) {
      try {
        const j = JSON.parse(readFileSync(pj, "utf8"));
        if (!j.name || !j.version) v.push(`${p}/package.json needs name and version`);
      } catch { v.push(`${p}/package.json is not valid JSON`); }
    }
  }

  // Walk tree
  const walk = (dir) => {
    for (const name of readdirSync(dir)) {
      if (SKIP_DIRS.has(name)) continue;
      const full = join(dir, name);
      const r = rel(full);
      if (statSync(full).isDirectory()) { walk(full); continue; }

      if (BAD_NAME.test(name)) v.push(`meaningless file name: ${r}`);

      if (TEST_FILE.test(name) && !/(^|\/)tests\//.test(r)) v.push(`test file outside a tests/ directory: ${r}`);
      if (DATASET_FILE.test(name) && !r.startsWith("datasets/") && !r.startsWith("tests/")) {
        v.push(`dataset file outside datasets/: ${r}`);
      }
      if (/\.mdx?$/i.test(name) && !r.startsWith("docs/") && !/^(README\.md|SECURITY\.md)$/.test(name)) {
        v.push(`documentation outside docs/: ${r}`);
      }

      if (!SECRET_SCAN_EXEMPT.some((re) => re.test(r)) && statSync(full).size <= SECRET_SCAN_MAX_BYTES) {
        let text;
        try { text = readFileSync(full, "utf8"); } catch { continue; }
        if (text.includes("\u0000")) continue; // binary
        if (name === "validate-structure.mjs") continue; // contains the patterns themselves
        for (const [label, re] of SECRET_PATTERNS) {
          if (re.test(text)) v.push(`possible committed secret (${label}): ${r}`);
        }
        if (/^\.env(\..+)?$/.test(name) && name !== ".env.example") v.push(`env file must not be committed: ${r}`);
      }
      if (/^\.env(\..+)?$/.test(name) && name !== ".env.example") v.push(`env file must not be committed: ${r}`);
      if (/\.(pem|p12|pfx)$/i.test(name) || /^id_(rsa|ed25519)/.test(name)) v.push(`key material must not be committed: ${r}`);
    }
  };
  walk(root);
  return [...new Set(v)];
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const root = resolve(process.argv[2] ?? join(fileURLToPath(import.meta.url), "..", "..", ".."));
  const violations = validate(root);
  if (violations.length) {
    console.error(`Structure validation FAILED (${violations.length}):`);
    for (const x of violations) console.error(`  - ${x}`);
    process.exit(1);
  }
  console.log(`Structure validation passed for ${basename(root)}.`);
}
