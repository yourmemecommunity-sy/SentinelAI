/**
 * End-to-end file scanning: real gateway + REAL Python security engine + REAL document-scanner (with its isolated parser
 * processes) + Postgres (PGlite). Real files: DOCX/XLSX/PDF/PNG/TXT, benign and hostile. Only the AI provider is absent
 * (files never go to a model here). Verifies the whole spec pipeline:
 *   upload -> type validation -> malware scan -> extraction -> PII/secret/injection scan -> policy -> allow/block/sanitize.
 */
import { execFileSync, spawn, type ChildProcess } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { FastifyInstance } from "fastify";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { AiRouter } from "@sentinelai/ai-router";
import { buildApp } from "../../src/app.js";
import { PgAuditLogWriter } from "../../src/events/auditLog.js";
import { PgEventSink } from "../../src/events/eventSink.js";
import { PgFileRepository } from "../../src/repositories/fileRepository.js";
import { PgPolicyRepository } from "../../src/repositories/policyRepository.js";
import { DbApiKeyAuthenticator, createApiKey } from "../../src/security/apiKeys.js";
import { HttpDocumentScanner } from "../../src/security/documentScanner.js";
import { HttpSecurityClient } from "../../src/security/securityClient.js";
import { FileScanService } from "../../src/services/fileScanService.js";
import { SecureAiService } from "../../src/services/secureAiService.js";
import { FakeProvider, PgliteTenantDb, TEST_CONFIG } from "../helpers/fakes.js";
import { createMigratedDb, type TestDb } from "../helpers/testDb.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "../../../..");
const ENGINE_DIR = resolve(ROOT, "services/security-engine");
const DOCS_DIR = resolve(ROOT, "services/document-scanner");
const VENV = (svc: string) => resolve(ROOT, "services", svc, process.platform === "win32" ? ".venv/Scripts/python.exe" : ".venv/bin/python");
const PY = process.env.SENTINEL_E2E_PYTHON ?? (existsSync(VENV("security-engine")) ? VENV("security-engine") : undefined);

const ENGINE_TOKEN = "e2e-engine-token-1234567890";
const DOCS_TOKEN = "e2e-docs-token-1234567890";
const PEPPER = "f".repeat(40);
// EICAR is a harmless standard AV test string. Built in memory only; writing it to disk would get the file quarantined.
const EICAR = Buffer.from("X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" + "!$H+H*");

const free = () => new Promise<number>((res, rej) => { const s = createServer(); s.once("error", rej); s.listen(0, "127.0.0.1", () => { const { port } = s.address() as { port: number }; s.close(() => res(port)); }); });
async function waitReady(url: string, what: string, logs: string[]) {
  for (let i = 0; i < 150; i++) { try { if ((await fetch(url)).ok) return; } catch { /* starting */ } await new Promise((r) => setTimeout(r, 300)); }
  throw new Error(`${what} did not become ready:\n${logs.slice(-10).join("\n")}`);
}

let engine: ChildProcess; let docs: ChildProcess; let db: TestDb; let app: FastifyInstance; let samples: string; let key: string; let keyB: string;
let policies: PgPolicyRepository; let orgA = ""; let tdb: PgliteTenantDb;
const logs: string[] = [];
const sample = (name: string) => readFileSync(join(samples, name));
const upload = (data: Buffer, filename?: string, k = key) => app.inject({
  method: "POST", url: "/v1/files/scan", payload: data,
  headers: { "x-sentinel-api-key": k, "content-type": "application/octet-stream", ...(filename ? { "x-filename": encodeURIComponent(filename) } : {}) },
});
const scanOf = async (name: string, filename = name) => (await upload(sample(name), filename)).json();

describe.skipIf(!PY)("file scanning: gateway + real engine + real document-scanner (e2e)", () => {
  beforeAll(async () => {
    samples = mkdtempSync(join(tmpdir(), "sentinel-samples-"));
    execFileSync(PY!, [join(DOCS_DIR, "tests/make_samples.py"), samples], { cwd: DOCS_DIR, stdio: "pipe" });

    const [enginePort, docsPort] = [await free(), await free()];
    engine = spawn(PY!, ["-m", "uvicorn", "app.main:app", "--port", String(enginePort), "--log-level", "warning"], {
      cwd: ENGINE_DIR, env: { ...process.env, SECURITY_ENGINE_TOKEN: ENGINE_TOKEN, SENTINEL_ENV: "development" }, stdio: ["ignore", "ignore", "pipe"] });
    engine.stderr?.on("data", (d) => logs.push(`[engine] ${d}`));
    docs = spawn(PY!, ["-m", "uvicorn", "app.main:app", "--port", String(docsPort), "--log-level", "warning"], {
      cwd: DOCS_DIR, env: { ...process.env, DOC_SCANNER_TOKEN: DOCS_TOKEN, SENTINEL_ENV: "development", MALWARE_SCANNER: "eicar", TESSERACT_CMD: "tesseract-not-installed-for-tests" }, stdio: ["ignore", "ignore", "pipe"] });
    docs.stderr?.on("data", (d) => logs.push(`[docs] ${d}`));
    await Promise.all([waitReady(`http://127.0.0.1:${enginePort}/ready`, "engine", logs), waitReady(`http://127.0.0.1:${docsPort}/ready`, "document-scanner", logs)]);

    db = await createMigratedDb();
    tdb = new PgliteTenantDb(db);
    const mkOrg = async (slug: string, zero = false) => (await db.query<{ id: string }>("INSERT INTO organizations (name, slug, zero_retention) VALUES ($1,$1,$2) RETURNING id", [slug, zero])).rows[0]!.id;
    orgA = await mkOrg("files-a"); const orgB = await mkOrg("files-b");
    key = (await createApiKey(tdb, PEPPER, { organizationId: orgA, name: "k", role: "DEVELOPER" })).key;
    keyB = (await createApiKey(tdb, PEPPER, { organizationId: orgB, name: "kb", role: "DEVELOPER" })).key;

    const scanner = new HttpSecurityClient({ baseUrl: `http://127.0.0.1:${enginePort}`, token: ENGINE_TOKEN, timeoutMs: 5000 });
    const documents = new HttpDocumentScanner({ baseUrl: `http://127.0.0.1:${docsPort}`, token: DOCS_TOKEN, timeoutMs: 60_000 });
    const events = new PgEventSink(tdb); policies = new PgPolicyRepository(tdb);
    app = buildApp({
      config: { ...TEST_CONFIG, apiKeyPepper: PEPPER, maxFileBytes: 200_000 }, scanner, events, policies, auditLog: new PgAuditLogWriter(tdb), auth: new DbApiKeyAuthenticator(tdb, PEPPER), ping: () => tdb.ping(),
      service: new SecureAiService({ scanner, router: new AiRouter().register(new FakeProvider()), policies, events }),
      documents, fileScan: new FileScanService({ documents, scanner, policies, events, files: new PgFileRepository(tdb) }),
    }, { logger: false });
  }, 180_000);

  afterAll(async () => { await app?.close(); engine?.kill(); docs?.kill(); await db?.close(); if (samples) rmSync(samples, { recursive: true, force: true }); });

  it("both services are up and the gateway reports the document scanner as ready", async () => {
    // Readiness is a probe and is retried like one: the engine's canary has a 1.5 s budget and (correctly) reports not-ready when a
    // loaded machine, e.g. several e2e suites running in parallel, misses it once. Persistent unreadiness still fails the test.
    let body: unknown;
    for (let i = 0; i < 20; i++) {
      body = (await app.inject({ method: "GET", url: "/ready" })).json();
      if ((body as { status?: string }).status === "ready") break;
      await new Promise((r) => setTimeout(r, 500));
    }
    expect(body).toMatchObject({ status: "ready", security_engine: true, database: true, document_scanner: true });
  });

  it("a clean DOCX is ALLOWED and its extracted text is returned", async () => {
    const b = await scanOf("clean.docx");
    expect(b).toMatchObject({ decision: "ALLOW", blocked: false, file: { detected_type: "docx", size: sample("clean.docx").length } });
    expect(b.sanitized_text).toContain("Quarterly summary: revenue grew four percent");
    expect(b.sanitized_text).toContain("Acme internal memo");            // header extracted
    expect(b.file.sha256).toBe(createHash("sha256").update(sample("clean.docx")).digest("hex"));
  });

  it("PII inside a DOCX is MASKED in the returned text (real engine)", async () => {
    const b = await scanOf("pii.docx");
    expect(b).toMatchObject({ decision: "MASK", blocked: false });
    expect(b.sanitized_text).toContain("j***@example.com");
    expect(b.sanitized_text).not.toContain("jane.doe@example.com");
    expect(b.detections.map((d: { entity: string }) => d.entity)).toContain("EMAIL");
  });

  it("a card number stored as a NUMERIC spreadsheet cell is detected and BLOCKED", async () => {
    const b = await scanOf("card.xlsx");
    expect(b).toMatchObject({ decision: "BLOCK", blocked: true, sanitized_text: null });
    expect(b.detections.map((d: { entity: string }) => d.entity)).toContain("CREDIT_CARD");
    expect(JSON.stringify(b)).not.toContain("4111111111111111");
  });

  it("prompt injection inside a PDF is BLOCKED", async () => {
    const b = await scanOf("injection.pdf");
    expect(b).toMatchObject({ decision: "BLOCK", blocked: true });
    expect(b.detections.map((d: { entity: string }) => d.entity)).toEqual(expect.arrayContaining(["PROMPT_INJECTION"]));
  });

  it("INDIRECT injection hidden as white text in a DOCX is found, BLOCKED, and the hiding is reported", async () => {
    const b = await scanOf("hidden_injection.docx");
    expect(b).toMatchObject({ decision: "BLOCK", blocked: true });
    expect(b.detections.map((d: { entity: string }) => d.entity)).toContain("PROMPT_INJECTION");
    expect(b.findings.map((f: { type: string }) => f.type)).toContain("hidden_text");
  });

  it("a secret in a text file is BLOCKED", async () => {
    const b = await scanOf("secret.txt");
    expect(b).toMatchObject({ decision: "BLOCK", blocked: true });
    expect(b.detections.map((d: { entity: string }) => d.entity)).toContain("AWS_CREDENTIAL");
  });

  it.each([
    ["macro.docx", "macros_present"], ["js.pdf", "pdf_active_content"], ["objstm_js.pdf", "pdf_active_content"], ["bomb.docx", "zip_bomb"],
    ["mismatch.pdf", "extension_mismatch"],
  ])("hostile file %s is BLOCKED by the document scanner with reason %s (no text, real audit event)", async (name, reason) => {
    const b = await scanOf(name);
    expect(b).toMatchObject({ decision: "BLOCK", blocked: true, reason, sanitized_text: null, failed_closed: false });
    expect(b.event_id).toBeTruthy();
  });

  it("malware (EICAR), executables and unsupported binaries are BLOCKED whatever they are named", async () => {
    expect((await upload(Buffer.concat([Buffer.from("harmless header\n"), EICAR]), "notes.txt")).json()).toMatchObject({ decision: "BLOCK", reason: "malware_detected" });
    expect((await upload(Buffer.concat([Buffer.from("MZ\x90\x00"), Buffer.alloc(200)]), "invoice.txt")).json()).toMatchObject({ decision: "BLOCK", reason: "executable_content" });
    expect((await upload(Buffer.from([0x1f, 0x8b, 0x08, 0, 0, 0, 0, 0]), "data.txt")).json()).toMatchObject({ decision: "BLOCK", reason: "unsupported_type" });
    expect((await upload(Buffer.from("just text"), "script.ps1")).json()).toMatchObject({ decision: "BLOCK", reason: "unsupported_type" });
  });

  it("images are BLOCKED when their text cannot be inspected (no working OCR here), and header-declared bombs are rejected first", async () => {
    const b = await scanOf("photo.png");
    expect(b).toMatchObject({ decision: "BLOCK", blocked: true });
    expect(b.reason).toMatch(/^ocr_/);
    expect((await scanOf("big_dims.png")).reason).toBe("image_too_large");
  });

  it("the ORG POLICY applies to files exactly as it does to prompts (EMAIL -> REDACT)", async () => {
    await policies.createVersion(orgA, "docs", [{ entity: "EMAIL", action: "REDACT" }], null);
    const b = await scanOf("pii.docx");
    expect(b).toMatchObject({ decision: "REDACT" });
    expect(b.sanitized_text).toContain("[EMAIL_REDACTED]");
    expect(b.policy_id).toContain("docs@1");
  });

  it("oversized uploads are rejected at the gateway (413) before reaching any service", async () => {
    expect((await upload(Buffer.alloc(300_000, 65), "big.txt")).statusCode).toBe(413);
  });

  it("every decision was audited as a file_scan event, and the DB holds metadata only", async () => {
    const ev = (await db.query<{ event_type: string; action: string }>("SELECT event_type, action FROM security_events WHERE organization_id = $1", [orgA])).rows;
    expect(ev.length).toBeGreaterThanOrEqual(10);
    expect(new Set(ev.map((e) => e.event_type))).toEqual(new Set(["file_scan"]));
    // files/file_scans exist only for retaining orgs (this org retains): hashes + verdicts, no content.
    const files = (await db.query<{ sha256: string; storage_key: string | null; verdict: string }>("SELECT f.sha256, f.storage_key, s.verdict FROM files f JOIN file_scans s ON s.file_id = f.id")).rows;
    expect(files.length).toBeGreaterThanOrEqual(10);
    expect(files.every((f) => f.storage_key === null && /^[0-9a-f]{64}$/.test(f.sha256))).toBe(true);
    expect(new Set(files.map((f) => f.verdict))).toEqual(expect.objectContaining(new Set(["CLEAN", "SANITIZED", "BLOCKED"])));

    const tables = (await db.query<{ table_name: string }>("SELECT table_name FROM information_schema.tables WHERE table_schema='public' AND table_type='BASE TABLE'")).rows;
    let dump = "";
    for (const t of tables) dump += JSON.stringify((await db.query(`SELECT * FROM ${t.table_name}`)).rows);
    for (const secret of ["jane.doe", "Quarterly summary", "revenue grew", "4111111111111111", "previous instructions", "system prompt", "DOCSCANNER012345", "Acme internal memo"]) {
      expect(dump, `DB contains "${secret}"`).not.toContain(secret);
    }
  });

  it("file metadata is tenant-isolated: another organization sees none of it", async () => {
    const other = await tdb.withTenant((await db.query<{ id: string }>("SELECT id FROM organizations WHERE slug = 'files-b'")).rows[0]!.id, async (q) => (await q.query("SELECT 1 FROM files")).rows.length);
    expect(other).toBe(0);
    expect((await upload(sample("clean.docx"), "clean.docx", keyB)).json()).toMatchObject({ decision: "ALLOW" });
  });

  it("FAILS CLOSED when the document scanner dies: BLOCK, failed_closed, no text; /ready reports 503", async () => {
    docs.kill();
    await new Promise((r) => setTimeout(r, 800));
    const b = (await upload(sample("clean.docx"), "clean.docx")).json();
    expect(b).toMatchObject({ decision: "BLOCK", blocked: true, failed_closed: true, reason: "scanner_unreachable", sanitized_text: null });
    expect((await app.inject({ method: "GET", url: "/ready" })).statusCode).toBe(503);
  });
});
