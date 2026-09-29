/**
 * DEVELOPMENT ONLY. Runs the real gateway on an in-memory Postgres (PGlite) so the whole product can be exercised without
 * Docker or a database server. Refuses to start in production. Data is lost on exit.
 *
 *   SECURITY_ENGINE_URL=http://127.0.0.1:8001 npx tsx dev/devServer.ts
 */
import { pathToFileURL } from "node:url";
import { resolve } from "node:path";
import { PGlite } from "@electric-sql/pglite";
import { AiRouter, type AIProvider, type ChatRequest, type ChatResponse } from "@sentinelai/ai-router";
import { registerConfiguredProviders } from "../src/providers/registry.js";
import { buildApp } from "../src/app.js";
import type { AppConfig } from "../src/config/env.js";
import type { Queryable, TenantDb } from "../src/db/tenantDb.js";
import { PgAuditLogWriter } from "../src/events/auditLog.js";
import { PgEventSink } from "../src/events/eventSink.js";
import { PgApiKeyRepository } from "../src/repositories/apiKeyRepository.js";
import { PgFileRepository } from "../src/repositories/fileRepository.js";
import { HttpDocumentScanner } from "../src/security/documentScanner.js";
import { FileScanService } from "../src/services/fileScanService.js";
import { HttpTokenVault } from "../src/security/tokenVault.js";
import { SecureStreamService } from "../src/services/secureStreamService.js";
import { PgAuthRepository } from "../src/repositories/authRepository.js";
import { PgPolicyRepository } from "../src/repositories/policyRepository.js";
import { DbApiKeyAuthenticator, createApiKey } from "../src/security/apiKeys.js";
import { CompositeAuthenticator } from "../src/security/authenticators.js";
import { HttpSecurityClient } from "../src/security/securityClient.js";
import { AccessTokens } from "../src/security/tokens.js";
import { AuthService } from "../src/services/authService.js";
import { SecureAiService } from "../src/services/secureAiService.js";

if (process.env.NODE_ENV === "production") throw new Error("devServer must never run in production");

/** Echoes the (already sanitized) prompt back, so the dashboard shows exactly what a real model would have received. */
class EchoProvider implements AIProvider {
  readonly id = "echo";
  async chat(req: ChatRequest): Promise<ChatResponse> {
    const last = [...req.messages].reverse().find((m) => m.role === "user")?.content ?? "";
    return { model: "echo-1", content: `You said: ${last}` };
  }
  generate(): Promise<ChatResponse> { throw new Error("unused"); }
  // eslint-disable-next-line require-yield
  async *stream(): AsyncGenerator<never> { throw new Error("unused"); }
  async validate() { return true; }
  async getModels() { return [{ id: "echo-1", provider: "echo", displayName: "Echo (dev)" }]; }
}

class PgliteTenantDb implements TenantDb {
  constructor(private readonly db: PGlite) {}
  private run<T>(org: string, fn: (q: Queryable) => Promise<T>): Promise<T> {
    return this.db.transaction(async (tx) => {
      await tx.exec("SET LOCAL ROLE sentinel_app");
      await tx.query("SELECT set_config('app.org_id', $1, true)", [org]);
      return fn(tx as unknown as Queryable);
    });
  }
  withTenant<T>(orgId: string, fn: (q: Queryable) => Promise<T>) { return this.run(orgId, fn); }
  withoutTenant<T>(fn: (q: Queryable) => Promise<T>) { return this.run("", fn); }
  async ping() { try { await this.db.query("SELECT 1"); return true; } catch { return false; } }
  async close() { await this.db.close(); }
}

async function main(): Promise<void> {
  const port = Number(process.env.API_PORT ?? 4000);
  const engineUrl = process.env.SECURITY_ENGINE_URL ?? "http://127.0.0.1:8001";
  const pgl = new PGlite();
  const migrate = await import(pathToFileURL(resolve(process.cwd(), "../../scripts/database/migrate.mjs")).href);
  await migrate.runMigrations({ exec: (s: string) => pgl.exec(s), query: (s: string, p?: unknown[]) => pgl.query(s, p) },
    resolve(process.cwd(), "../../scripts/database/migrations"));
  const db = new PgliteTenantDb(pgl);

  const config: AppConfig = {
    nodeEnv: "development", port, corsOrigins: ["http://localhost:3000"], apiKeyPepper: "dev-only-pepper-".padEnd(40, "x"),
    securityEngineUrl: engineUrl, securityEngineToken: process.env.SECURITY_ENGINE_TOKEN, securityTimeoutMs: 3000, securityTimeoutPerKcharMs: 60,
    databaseUrl: undefined, geminiApiKey: process.env.GEMINI_API_KEY, openaiApiKey: process.env.OPENAI_API_KEY,
    anthropicApiKey: process.env.ANTHROPIC_API_KEY,
    ollama: process.env.OLLAMA_MODEL ? { baseUrl: process.env.OLLAMA_BASE_URL ?? "http://127.0.0.1:11434", model: process.env.OLLAMA_MODEL } : undefined, maxInputChars: 200_000, maxFileBytes: 20 * 1024 * 1024,
    vault: process.env.VAULT_URL ? { url: process.env.VAULT_URL, token: process.env.VAULT_TOKEN, timeoutMs: 1000 } : undefined,
    stream: { holdBackChars: 256, minSegmentChars: 64, idleTimeoutMs: 30_000, maxDurationMs: 300_000, maxOutputChars: 200_000, maxConcurrent: 10 },
    documentScanner: process.env.DOCUMENT_SCANNER_URL ? { url: process.env.DOCUMENT_SCANNER_URL, token: process.env.DOCUMENT_SCANNER_TOKEN, timeoutMs: 60_000 } : undefined, rateLimitPerMinute: 600,
    jwtAccessSecret: "dev-only-jwt-secret-".padEnd(40, "y"), accessTtlSeconds: 900, refreshTtlSeconds: 30 * 86_400, signupEnabled: true,
  };
  const tokens = new AccessTokens({ secret: config.jwtAccessSecret!, ttlSeconds: config.accessTtlSeconds });
  const scanner = new HttpSecurityClient({ baseUrl: engineUrl, token: config.securityEngineToken, timeoutMs: config.securityTimeoutMs });
  const router = new AiRouter().register(new EchoProvider());
  registerConfiguredProviders(router, config);
  const events = new PgEventSink(db); const policies = new PgPolicyRepository(db); const auditLog = new PgAuditLogWriter(db);

  const documents = config.documentScanner ? new HttpDocumentScanner({ baseUrl: config.documentScanner.url, token: config.documentScanner.token, timeoutMs: 60_000 }) : undefined;
  const vault = config.vault ? new HttpTokenVault({ baseUrl: config.vault.url, token: config.vault.token, timeoutMs: config.vault.timeoutMs }) : undefined;
  const service = new SecureAiService({ scanner, router, policies, events, vault });
  const app = buildApp({
    ...(documents ? { documents, fileScan: new FileScanService({ documents, scanner, policies, events, files: new PgFileRepository(db) }) } : {}),
    config, scanner, events, policies, auditLog, ping: () => db.ping(), apiKeys: new PgApiKeyRepository(db, config.apiKeyPepper),
    auth: new CompositeAuthenticator(new DbApiKeyAuthenticator(db, config.apiKeyPepper), tokens),
    service, ...(vault ? { vault } : {}), streaming: new SecureStreamService({ service, router, vault, limits: config.stream }),
    authService: new AuthService({ repo: new PgAuthRepository(db), tokens, audit: auditLog, accessTtlSeconds: 900, refreshTtlSeconds: config.refreshTtlSeconds }),
    signupEnabled: true,
    authLimits: { ipPerMinute: 600, emailPerMinute: 600 },
  });
  await app.listen({ port, host: "127.0.0.1" });

  // Dev convenience (there is no API-key management endpoint yet): seed a demo organization with a DEVELOPER key.
  const orgId = (await pgl.query<{ id: string }>("INSERT INTO organizations (name, slug) VALUES ('Dev Org', 'dev-org') RETURNING id")).rows[0]!.id;
  const seeded = await createApiKey(db, config.apiKeyPepper, { organizationId: orgId, name: "dev-seed", role: "DEVELOPER" });
  console.log(`SENTINEL_DEV_API_KEY=${seeded.key}`);
  console.log(`[dev] gateway on http://127.0.0.1:${port} (in-memory Postgres; engine ${engineUrl}; providers: ${router.ids().join(", ")})`);
}

main().catch((e) => { console.error("[dev] fatal:", (e as Error).message); process.exit(1); });
