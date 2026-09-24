import { readFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import { COOKIE, CSRF_HEADER, DEFAULT_MAX_UPLOAD_BYTES, handleFileScan, syntheticFilename } from "@/lib/api/bff";

const SESSION = { access_token: "AT2", refresh_token: "snr_RT2", expires_in: 900, user: { id: "u1", organization_id: "o1", role: "OWNER" } };
const jsonRes = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
const deps = (f: (url: string, init?: RequestInit) => Promise<Response>, over: object = {}) => ({ gatewayUrl: "http://gw.test", fetch: f as unknown as typeof fetch, secure: false, ...over });

const BYTES = new Uint8Array([0x25, 0x50, 0x44, 0x46, 0x00, 0xff, 0xfe, 0x80]);
const HEADERS = { host: "dash.test", origin: "http://dash.test", [CSRF_HEADER]: "1", "content-type": "application/octet-stream", cookie: `${COOKIE.access}=AT1` };
const upload = (over: { headers?: Record<string, string | null>; body?: BodyInit | null; method?: string } = {}) => {
  const headers: Record<string, string> = { ...HEADERS };
  for (const [k, v] of Object.entries(over.headers ?? {})) { if (v === null) delete headers[k]; else headers[k] = v; }
  const body = over.body === undefined ? BYTES : over.body;
  return new Request("http://dash.test/api/files/scan", { method: over.method ?? "POST", headers, ...(body !== null ? { body, duplex: "half" } as RequestInit : {}) });
};
const stream = (chunks: Uint8Array[]) => new ReadableStream<Uint8Array>({ start(c) { for (const x of chunks) c.enqueue(x); c.close(); } });
const RESULT = { event_id: "e1", decision: "ALLOW", blocked: false, sanitized_text: "hello" };

describe("file upload through the BFF", () => {
  it("relays the EXACT bytes with the session bearer token as octet-stream, and relays the verdict", async () => {
    const f = vi.fn(async () => jsonRes(RESULT));
    const res = await handleFileScan(upload({ headers: { "x-filename": encodeURIComponent("Q3 salaries - jane.PDF") } }), deps(f));
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual(RESULT);
    expect(res.headers.get("cache-control")).toBe("no-store");
    const [url, init] = f.mock.calls[0]! as unknown as [string, RequestInit];
    expect(url).toBe("http://gw.test/v1/files/scan");
    expect(init.method).toBe("POST");
    expect(Buffer.from(init.body as Uint8Array).equals(Buffer.from(BYTES))).toBe(true);
    expect(init.headers).toEqual({ authorization: "Bearer AT1", "content-type": "application/octet-stream", "x-filename": encodeURIComponent("upload.pdf") });
  });

  it("never forwards the real file name (only a synthetic upload.<ext>) and never forwards the browser's cookies", async () => {
    const f = vi.fn(async () => jsonRes(RESULT));
    await handleFileScan(upload({ headers: { "x-filename": encodeURIComponent("board-minutes-jane.doe@example.com.docx") } }), deps(f));
    const init = (f.mock.calls[0] as unknown as [string, RequestInit])[1];
    expect(JSON.stringify(init.headers)).not.toMatch(/jane|board|cookie|snr_/i);
    expect((init.headers as Record<string, string>)["x-filename"]).toBe(encodeURIComponent("upload.docx"));
  });

  it("syntheticFilename keeps only a safe extension", () => {
    const enc = encodeURIComponent;
    expect(syntheticFilename(enc("a b.PDF"))).toBe(enc("upload.pdf"));
    expect(syntheticFilename(enc("noext"))).toBeNull();
    expect(syntheticFilename(enc("x.tar.gz"))).toBe(enc("upload.gz"));
    expect(syntheticFilename(enc("x.p df"))).toBeNull();
    expect(syntheticFilename(enc("x." + "a".repeat(9)))).toBeNull();
    expect(syntheticFilename("%E0%A4%A")).toBeNull();
    expect(syntheticFilename("a".repeat(2000) + ".pdf")).toBeNull();
    expect(syntheticFilename(null)).toBeNull();
    expect(syntheticFilename(enc("../../etc/passwd"))).toBeNull();
  });

  it("rejects, WITHOUT calling the gateway: wrong method 405, no CSRF 403, no credentials 401, wrong content type 415, empty 422", async () => {
    const f = vi.fn();
    const d = deps(f as never);
    expect((await handleFileScan(upload({ method: "PUT" }), d)).status).toBe(405);
    expect((await handleFileScan(upload({ headers: { [CSRF_HEADER]: null } }), d)).status).toBe(403);
    expect((await handleFileScan(upload({ headers: { origin: "http://evil.test" } }), d)).status).toBe(403);
    expect((await handleFileScan(upload({ headers: { cookie: null } }), d)).status).toBe(401);
    expect((await handleFileScan(upload({ headers: { "content-type": "application/json" } }), d)).status).toBe(415);
    expect((await handleFileScan(upload({ headers: { "content-type": "multipart/form-data; boundary=x" } }), d)).status).toBe(415);
    expect((await handleFileScan(upload({ body: new Uint8Array(0) }), d)).status).toBe(422);
    expect(f).not.toHaveBeenCalled();
  });

  it("checks credentials BEFORE reading the body (an unauthenticated caller cannot make the BFF buffer a large upload)", async () => {
    const r = upload({ headers: { cookie: null }, body: new Uint8Array(1000) });
    expect((await handleFileScan(r, deps(vi.fn() as never))).status).toBe(401);
    expect(r.bodyUsed).toBe(false);
    const wrongType = upload({ headers: { "content-type": "application/json" }, body: new Uint8Array(1000) });
    expect((await handleFileScan(wrongType, deps(vi.fn() as never))).status).toBe(415);
    expect(wrongType.bodyUsed).toBe(false);
  });

  it("enforces the size cap up front (Content-Length) and while streaming (no Content-Length), without calling the gateway", async () => {
    const f = vi.fn();
    const d = deps(f as never, { maxUploadBytes: 100 });
    expect((await handleFileScan(upload({ headers: { "content-length": "101" }, body: new Uint8Array(101) }), d)).status).toBe(413);
    const res = await handleFileScan(upload({ body: stream([new Uint8Array(60), new Uint8Array(60)]) }), d);
    expect(res.status).toBe(413);
    expect(await res.json()).toEqual({ error: "payload_too_large" });
    expect(f).not.toHaveBeenCalled();
    expect(DEFAULT_MAX_UPLOAD_BYTES).toBe(20 * 1024 * 1024);
  });

  it("stops reading as soon as the cap is exceeded", async () => {
    let pulls = 0;
    const body = new ReadableStream<Uint8Array>({ pull(c) { pulls++; c.enqueue(new Uint8Array(1000)); } });
    const res = await handleFileScan(upload({ body }), deps(vi.fn() as never, { maxUploadBytes: 500 }));
    expect(res.status).toBe(413);
    expect(pulls).toBeLessThan(10);
  });

  it("a body shorter than its declared Content-Length (truncated in transit) is REJECTED, not scanned", async () => {
    const f = vi.fn();
    const res = await handleFileScan(upload({ headers: { "content-length": "1000" }, body: stream([new Uint8Array(10)]) }), deps(f as never));
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "incomplete_upload" });
    expect(f).not.toHaveBeenCalled();
    expect((await handleFileScan(upload({ headers: { "content-length": "abc" } }), deps(f as never))).status).toBe(400);
    expect((await handleFileScan(upload({ headers: { "content-length": "-1" } }), deps(f as never))).status).toBe(400);
  });

  it("relays gateway statuses unchanged: 403 (no scan permission), 413, 429, 503 (audit unavailable)", async () => {
    for (const status of [403, 413, 429, 503]) {
      const res = await handleFileScan(upload(), deps(async () => jsonRes({ error: `e${status}` }, status)));
      expect(res.status).toBe(status);
      expect(await res.json()).toEqual({ error: `e${status}` });
    }
  });

  it("a BLOCK verdict stays a 200 with no text", async () => {
    const blocked = { ...RESULT, decision: "BLOCK", blocked: true, reason: "macros_present", sanitized_text: null };
    const res = await handleFileScan(upload(), deps(async () => jsonRes(blocked)));
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ blocked: true, sanitized_text: null });
  });

  it("gateway unreachable -> 502 and the file is not retried elsewhere", async () => {
    const f = vi.fn(async () => { throw new TypeError("ECONNREFUSED"); });
    expect((await handleFileScan(upload(), deps(f))).status).toBe(502);
    expect(f).toHaveBeenCalledTimes(1);
  });

  it("an expired access token is refreshed once and the SAME bytes are re-sent with the new token", async () => {
    const seen: { url: string; auth: string; bytes: Buffer | null }[] = [];
    const f = async (url: string, init?: RequestInit) => {
      const auth = (init?.headers as Record<string, string> | undefined)?.authorization ?? "";
      seen.push({ url: url.replace("http://gw.test", ""), auth, bytes: init?.body ? Buffer.from(init.body as Uint8Array) : null });
      if (url.endsWith("/v1/auth/refresh")) return jsonRes(SESSION);
      return auth === "Bearer AT2" ? jsonRes(RESULT) : jsonRes({ error: "unauthorized" }, 401);
    };
    const res = await handleFileScan(upload({ headers: { cookie: `${COOKIE.access}=OLD; ${COOKIE.refresh}=snr_RT_FILE_A` } }), deps(f));
    expect(res.status).toBe(200);
    expect(res.headers.getSetCookie().join("|")).toContain("sn_at=AT2");
    expect(seen.map((s) => s.url)).toEqual(["/v1/files/scan", "/v1/auth/refresh", "/v1/files/scan"]);
    expect(seen[2]!.bytes!.equals(Buffer.from(BYTES))).toBe(true);
  });

  it("a session that cannot be refreshed gets 401 and cleared cookies", async () => {
    const f = async (url: string) => (url.endsWith("/v1/auth/refresh") ? jsonRes({ error: "invalid" }, 401) : jsonRes({ error: "unauthorized" }, 401));
    const res = await handleFileScan(upload({ headers: { cookie: `${COOKIE.access}=OLD; ${COOKIE.refresh}=snr_RT_FILE_B` } }), deps(f));
    expect(res.status).toBe(401);
    expect(res.headers.getSetCookie().every((c) => c.includes("Max-Age=0"))).toBe(true);
  });
});

describe("middleware keeps upload bodies out of Next's body-cloning path", () => {
  it("api/files is excluded from the middleware matcher, other routes are not", () => {
    const src = readFileSync(new URL("../middleware.ts", import.meta.url), "utf-8");
    const m = /matcher:\s*\["([^"]+)"\]/.exec(src);
    expect(m).not.toBeNull();
    const re = new RegExp(`^${m![1]!}$`);
    expect(re.test("/api/files/scan")).toBe(false);
    expect(re.test("/api/proxy/events")).toBe(true);
    expect(re.test("/dashboard")).toBe(true);
    expect(re.test("/files")).toBe(true);
  });
});
