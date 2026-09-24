import { createServer, type Server, type Socket } from "node:net";
import Fastify from "fastify";
import { afterEach, describe, expect, it } from "vitest";
import { PgTenantDb } from "../../src/db/tenantDb.js";
import { authenticated, requirePermission } from "../../src/middleware/auth.js";
import type { ApiKeyAuthenticator } from "../../src/security/apiKeys.js";
import { principal } from "../helpers/fakes.js";

/**
 * Found by stopping the Postgres container: requests HUNG (pg's pool has no connect timeout by default) and, once they did
 * fail, every valid client was told its key was invalid (401). These pin down the fixed behaviour.
 */
const servers: Server[] = [];
const sockets: Socket[] = [];
afterEach(async () => {
  for (const s of sockets.splice(0)) s.destroy();
  await Promise.all(servers.splice(0).map((s) => new Promise<void>((r) => s.close(() => r()))));
});

/** A "database" that accepts TCP connections and then never says a word: exactly what a wedged Postgres looks like. */
async function blackhole(): Promise<number> {
  const srv = createServer((sock) => { sockets.push(sock); });
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  servers.push(srv);
  return (srv.address() as { port: number }).port;
}

describe("database outage", () => {
  it("acquiring a connection to a wedged server fails within the connect timeout instead of hanging", async () => {
    const port = await blackhole();
    const db = new PgTenantDb(`postgresql://u:p@127.0.0.1:${port}/db`, false, { connectTimeoutMs: 800 });
    const t0 = Date.now();
    await expect(db.withoutTenant(async (q) => q.query("SELECT 1"))).rejects.toThrow();
    const elapsed = Date.now() - t0;
    expect(elapsed).toBeGreaterThanOrEqual(700);
    expect(elapsed).toBeLessThan(5_000);
    expect(await db.ping()).toBe(false);
    await db.close();
  });

  it("the default connect timeout is bounded (not pg's infinite default)", async () => {
    const port = await blackhole();
    const db = new PgTenantDb(`postgresql://u:p@127.0.0.1:${port}/db`);
    const t0 = Date.now();
    await expect(db.ping()).resolves.toBe(false);
    expect(Date.now() - t0).toBeLessThan(8_000);
    await db.close();
  }, 15_000);
});

describe("authentication when credentials cannot be verified", () => {
  const throwing: ApiKeyAuthenticator = { authenticate: async () => { throw new Error("connection timeout"); } };
  const denying: ApiKeyAuthenticator = { authenticate: async () => null };
  const allowing: ApiKeyAuthenticator = { authenticate: async () => principal({ role: "DEVELOPER" }) };

  async function app(auth: ApiKeyAuthenticator) {
    const a = Fastify();
    a.get("/p", { preHandler: requirePermission(auth, "scan:use") }, async () => ({ ok: true }));
    a.get("/a", { preHandler: authenticated(auth) }, async () => ({ ok: true }));
    await a.ready();
    return a;
  }

  it("an unverifiable credential is 503 auth_unavailable (refused, but not called invalid)", async () => {
    const a = await app(throwing);
    for (const url of ["/p", "/a"]) {
      const r = await a.inject({ method: "GET", url, headers: { "x-sentinel-api-key": "anything" } });
      expect(r.statusCode, url).toBe(503);
      expect(r.json()).toEqual({ error: "auth_unavailable" });
      expect(r.headers["retry-after"]).toBe("5");
      expect(r.body).not.toContain("ok");
    }
    await a.close();
  });

  it("a genuinely invalid credential is still 401, and a valid one still passes", async () => {
    const d = await app(denying);
    expect((await d.inject({ method: "GET", url: "/p" })).statusCode).toBe(401);
    await d.close();
    const ok = await app(allowing);
    expect((await ok.inject({ method: "GET", url: "/p" })).json()).toEqual({ ok: true });
    await ok.close();
  });

  it("the 503 does not depend on the key presented (no oracle for which keys exist)", async () => {
    const a = await app(throwing);
    const bodies = new Set<string>();
    for (const key of [undefined, "short", "snl_" + "a".repeat(8) + "_" + "b".repeat(43)]) {
      const r = await a.inject({ method: "GET", url: "/p", headers: key ? { "x-sentinel-api-key": key } : {} });
      bodies.add(`${r.statusCode} ${r.body}`);
    }
    expect(bodies.size).toBe(1);
    await a.close();
  });
});
