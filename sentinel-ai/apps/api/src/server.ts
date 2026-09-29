import { AiRouter } from "@sentinelai/ai-router";
import { registerConfiguredProviders } from "./providers/registry.js";
import { buildApp } from "./app.js";
import { loadConfig } from "./config/env.js";
import { PgTenantDb } from "./db/tenantDb.js";
import { PgAuditLogWriter } from "./events/auditLog.js";
import { PgEventSink } from "./events/eventSink.js";
import { PgPolicyRepository } from "./repositories/policyRepository.js";
import { PgApiKeyRepository } from "./repositories/apiKeyRepository.js";
import { PgFileRepository } from "./repositories/fileRepository.js";
import { HttpDocumentScanner } from "./security/documentScanner.js";
import { FileScanService } from "./services/fileScanService.js";
import { HttpTokenVault } from "./security/tokenVault.js";
import { SecureStreamService } from "./services/secureStreamService.js";
import { PgAuthRepository } from "./repositories/authRepository.js";
import { DbApiKeyAuthenticator } from "./security/apiKeys.js";
import { CompositeAuthenticator } from "./security/authenticators.js";
import { AccessTokens } from "./security/tokens.js";
import { AuthService } from "./services/authService.js";
import { HttpSecurityClient } from "./security/securityClient.js";
import { SecureAiService } from "./services/secureAiService.js";
import { PgDirectoryRepository } from "./repositories/directoryRepository.js";
import { PgProviderRepository } from "./repositories/providerRepository.js";
import { OrgRouterSource } from "./providers/orgRouters.js";
import { CredentialCipher } from "./security/credentialCipher.js";

async function main(): Promise<void> {
  const config = loadConfig();
  if (!config.databaseUrl) throw new Error("DATABASE_URL is required");

  const db = new PgTenantDb(config.databaseUrl);
  // Fail closed on a database login that would silently switch tenant isolation off.
  const rls = await db.rlsStatus();
  if (!rls.enforced) {
    const msg = `row-level security is NOT enforced for database role "${rls.role}": ${rls.reason}. Connect as a login role that is a member of sentinel_app (see scripts/database/provision-app-role.mjs).`;
    if (config.nodeEnv === "production") throw new Error(msg);
    console.warn(`WARNING: ${msg}`);
  }
  const scanner = new HttpSecurityClient({ baseUrl: config.securityEngineUrl, token: config.securityEngineToken,
    timeoutMs: config.securityTimeoutMs, timeoutPerKcharMs: config.securityTimeoutPerKcharMs });
  const router = new AiRouter();
  registerConfiguredProviders(router, config);
  if (router.ids().length === 0) console.warn("no AI providers configured: all /v1/ai/* requests will be blocked as unknown_provider");

  const events = new PgEventSink(db);
  const policies = new PgPolicyRepository(db);
  const auditLog = new PgAuditLogWriter(db);
  const tokens = config.jwtAccessSecret ? new AccessTokens({ secret: config.jwtAccessSecret, ttlSeconds: config.accessTtlSeconds }) : undefined;
  const authService = tokens
    ? new AuthService({ repo: new PgAuthRepository(db), tokens, audit: auditLog, accessTtlSeconds: config.accessTtlSeconds, refreshTtlSeconds: config.refreshTtlSeconds })
    : undefined;
  const documents = config.documentScanner
    ? new HttpDocumentScanner({ baseUrl: config.documentScanner.url, token: config.documentScanner.token, timeoutMs: config.documentScanner.timeoutMs }) : undefined;
  const vault = config.vault ? new HttpTokenVault({ baseUrl: config.vault.url, token: config.vault.token, timeoutMs: config.vault.timeoutMs }) : undefined;
  const directory = new PgDirectoryRepository(db);
  const providerRepo = new PgProviderRepository(db);
  const cipher = config.providerCredentialKeys ? new CredentialCipher(config.providerCredentialKeys) : undefined;
  if (!cipher) console.warn("PROVIDER_CREDENTIAL_KEYS not set: organizations cannot store their own provider credentials");
  const routers = new OrgRouterSource({ platform: router, repo: providerRepo, cipher });
  const service = new SecureAiService({ scanner, router, routers, policies, events, vault });
  const app = buildApp({
    config, scanner, events, policies,
    ...(documents ? { documents, fileScan: new FileScanService({ documents, scanner, policies, events, files: new PgFileRepository(db) }) } : {}),
    auth: new CompositeAuthenticator(new DbApiKeyAuthenticator(db, config.apiKeyPepper), tokens, directory),
    directory, providerSettings: { repo: providerRepo, routers, cipher, platformProviders: router.ids() },
    auditLog, apiKeys: new PgApiKeyRepository(db, config.apiKeyPepper),
    ...(authService ? { authService, signupEnabled: config.signupEnabled } : {}),
    service, ...(vault ? { vault } : {}), streaming: new SecureStreamService({ service, vault, limits: config.stream }),
    ping: () => db.ping(),
  });

  const shutdown = async () => { await app.close(); await db.close(); process.exit(0); };
  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);
  await app.listen({ port: config.port, host: "0.0.0.0" });
}

main().catch((err) => {
  console.error("fatal:", (err as Error).message); // message only: config errors never contain secret values
  process.exit(1);
});
