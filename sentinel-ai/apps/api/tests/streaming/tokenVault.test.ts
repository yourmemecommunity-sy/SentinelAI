import { describe, expect, it, vi } from "vitest";
import { HttpTokenVault, VAULT_SESSION_ID, VaultUnavailableError, deriveVaultSession } from "../../src/security/tokenVault.js";
import { principal } from "../helpers/fakes.js";

const json = (b: unknown, status = 200) => new Response(JSON.stringify(b), { status });
const client = (f: typeof fetch, token: string | undefined = "vault-token-1234567") => new HttpTokenVault({ baseUrl: "http://vault.test", token, timeoutMs: 300, fetch: f });

describe("HttpTokenVault.resolve", () => {
  it("sends org, session and the distinct valid tokens with the internal token; refuses redirects", async () => {
    const f = vi.fn(async () => json({ values: { "[TOK_NAME_1]": "John Doe" } }));
    const got = await client(f as unknown as typeof fetch).resolve("org-1", "sess", ["[TOK_NAME_1]", "[TOK_NAME_1]", "junk", "[TOK_name_2]", "[TOK_EMAIL_9]"]);
    expect([...got]).toEqual([["[TOK_NAME_1]", "John Doe"]]);
    const [url, init] = f.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("http://vault.test/v1/vault/resolve");
    expect(init.redirect).toBe("error");
    expect(init.headers).toMatchObject({ "x-internal-token": "vault-token-1234567", "content-type": "application/json" });
    expect(JSON.parse(init.body as string)).toEqual({ organization_id: "org-1", session_id: "sess", tokens: ["[TOK_NAME_1]", "[TOK_EMAIL_9]"] });
  });

  it("makes no request at all when there is nothing valid to resolve", async () => {
    const f = vi.fn();
    expect((await client(f as never).resolve("o", "s", ["nope", "[TOK_x_1]"])).size).toBe(0);
    expect(f).not.toHaveBeenCalled();
  });

  it("only returns tokens it asked about (a misbehaving vault cannot inject text for other tokens)", async () => {
    const f = vi.fn(async () => json({ values: { "[TOK_NAME_1]": "ok", "[TOK_EMAIL_7]": "INJECTED", "anything": "INJECTED" } }));
    const got = await client(f as never).resolve("o", "s", ["[TOK_NAME_1]"]);
    expect([...got.keys()]).toEqual(["[TOK_NAME_1]"]);
  });

  it.each([
    ["network error", async () => { throw new TypeError("ECONNREFUSED"); }, "vault_unreachable"],
    ["HTTP 503", async () => json({}, 503), "vault_http_503"],
    ["HTTP 401", async () => json({}, 401), "vault_http_401"],
    ["non-JSON", async () => new Response("<html>", { status: 200 }), "vault_invalid_response"],
    ["wrong shape", async () => json({ values: [1] }), "vault_invalid_response"],
    ["non-string value", async () => json({ values: { "[TOK_NAME_1]": 5 } }), "vault_invalid_response"],
    ["oversized value", async () => json({ values: { "[TOK_NAME_1]": "x".repeat(20_000) } }), "vault_invalid_response"],
  ])("%s -> VaultUnavailableError (%s), never a partial result", async (_n, f, message) => {
    const err = await client(f as unknown as typeof fetch).resolve("o", "s", ["[TOK_NAME_1]"]).catch((e) => e);
    expect(err).toBeInstanceOf(VaultUnavailableError);
    expect(err.message).toBe(message);
  });

  it("a hung vault is cut off by the timeout", async () => {
    const f = (_u: string, init?: RequestInit) => new Promise<Response>((_res, rej) => init?.signal?.addEventListener("abort", () => rej(new DOMException("t", "TimeoutError"))));
    const t0 = Date.now();
    await expect(client(f as unknown as typeof fetch).resolve("o", "s", ["[TOK_NAME_1]"])).rejects.toBeInstanceOf(VaultUnavailableError);
    expect(Date.now() - t0).toBeLessThan(1500);
  });

  it("the caller's abort signal cancels the request", async () => {
    const ctl = new AbortController();
    const f = (_u: string, init?: RequestInit) => new Promise<Response>((_res, rej) => init?.signal?.addEventListener("abort", () => rej(new DOMException("a", "AbortError"))));
    const p = client(f as unknown as typeof fetch).resolve("o", "s", ["[TOK_NAME_1]"], ctl.signal);
    ctl.abort();
    await expect(p).rejects.toBeInstanceOf(VaultUnavailableError);
  });

  it("omits the internal-token header when none is configured (development)", async () => {
    const f = vi.fn(async () => json({ values: {} }));
    await new HttpTokenVault({ baseUrl: "http://vault.test", timeoutMs: 300, fetch: f as never }).resolve("o", "s", ["[TOK_NAME_1]"]);
    expect((f.mock.calls[0] as unknown as [string, RequestInit])[1].headers).not.toHaveProperty("x-internal-token");
  });
});

describe("HttpTokenVault other calls", () => {
  it("deleteSession accepts 204 and reports failures", async () => {
    await expect(client((async () => new Response(null, { status: 204 })) as never).deleteSession("o", "s")).resolves.toBeUndefined();
    await expect(client((async () => json({}, 503)) as never).deleteSession("o", "s")).rejects.toBeInstanceOf(VaultUnavailableError);
  });
  it("ready() is true only for a 2xx /ready and never throws", async () => {
    expect(await client((async () => json({ status: "ready" })) as never).ready()).toBe(true);
    expect(await client((async () => json({}, 503)) as never).ready()).toBe(false);
    expect(await client((async () => { throw new Error("down"); }) as never).ready()).toBe(false);
  });
});

describe("deriveVaultSession", () => {
  const a = principal({ apiKeyId: "key-a" });
  const b = principal({ apiKeyId: "key-b" });

  it("is deterministic for one caller and one client session id", () => {
    expect(deriveVaultSession(a, "conv-1")).toEqual(deriveVaultSession(a, "conv-1"));
    expect(deriveVaultSession(a, "conv-1").ephemeral).toBe(false);
  });

  it("two callers using the same session id get unrelated sessions (a caller cannot name someone else's)", () => {
    expect(deriveVaultSession(a, "shared").id).not.toBe(deriveVaultSession(b, "shared").id);
    expect(deriveVaultSession(principal({ organizationId: "22222222-2222-4222-8222-222222222222", apiKeyId: "key-a" }), "shared").id).not.toBe(deriveVaultSession(a, "shared").id);
    expect(deriveVaultSession(principal({ apiKeyId: null, userId: "u1" }), "shared").id).not.toBe(deriveVaultSession(principal({ apiKeyId: null, userId: "u2" }), "shared").id);
  });

  it("without a client id the session is random and ephemeral", () => {
    const x = deriveVaultSession(a, undefined); const y = deriveVaultSession(a, undefined);
    expect(x.ephemeral).toBe(true);
    expect(x.id).not.toBe(y.id);
  });

  it("the id never contains the client-supplied text and always satisfies the vault's id grammar", () => {
    const s = deriveVaultSession(a, "my-secret-conversation-name");
    expect(s.id).toMatch(/^[0-9a-f]{40}$/);
    expect(s.id).not.toContain("secret");
    expect(VAULT_SESSION_ID.test(s.id)).toBe(true);
    expect(VAULT_SESSION_ID.test("s\n")).toBe(false);
  });
});
