/**
 * Regressions for two defects found by fuzzing the running gateway (scripts/development/api-fuzz.mjs):
 *  1. a team name containing NUL or a lone UTF-16 surrogate reached PostgreSQL and came back as HTTP 500;
 *  2. validation errors echoed client input ("received 'xyz'", unknown key names), contrary to the rule that errors never
 *     echo request bodies.
 */
import Fastify from "fastify";
import { describe, expect, it } from "vitest";
import { z } from "zod";
import { registerErrorHandler } from "../../src/middleware/hardening.js";
import { displayName, isCleanText } from "../../src/validators/schemas.js";

const MARK = "FZ" + "MARKER42";

function appWith(schema: z.ZodTypeAny, onValid?: () => never) {
  const app = Fastify();
  registerErrorHandler(app);
  app.post("/t", async (req) => { schema.parse(req.body); if (onValid) onValid(); return { ok: true }; });
  return app;
}

describe("persisted names reject text PostgreSQL cannot store", () => {
  it.each([
    ["NUL", `a\u0000${MARK}`], ["bell", `a\u0007b`], ["DEL", `a\u007Fb`], ["newline", "a\nb"],
    ["lone high surrogate", `\uD800${MARK}`], ["lone low surrogate", `x\uDC00y`],
  ])("rejects %s", (_n, v) => {
    expect(isCleanText(v)).toBe(false);
    expect(displayName(100).safeParse(v).success).toBe(false);
  });

  it.each([["plain", "Payments team"], ["accents", "Équipe sécurité"], ["emoji (valid surrogate pair)", "Blue 🛡️ team"], ["CJK", "安全团队"]])(
    "accepts %s", (_n, v) => { expect(displayName(100).safeParse(v).success).toBe(true); });

  it("a malformed name is a 422 from validation, never a 500", async () => {
    const app = appWith(z.object({ name: displayName(100) }).strict());
    const r = await app.inject({ method: "POST", url: "/t", payload: { name: `x\u0000${MARK}` } });
    expect(r.statusCode).toBe(422);
    expect(r.body).not.toContain(MARK);
  });

  it("if text PostgreSQL cannot store still reaches it, the answer is 400, not 500", async () => {
    const app = Fastify();
    registerErrorHandler(app);
    app.post("/t", async () => { throw Object.assign(new Error("invalid byte sequence for encoding \"UTF8\": 0x00"), { code: "22021" }); });
    const r = await app.inject({ method: "POST", url: "/t", payload: {} });
    expect(r.statusCode).toBe(400);
    expect(r.json()).toEqual({ error: "invalid_request", message: "text contains characters that cannot be stored" });
  });
});

describe("validation errors never echo client input", () => {
  it.each([
    ["enum value", z.object({ direction: z.enum(["INPUT", "OUTPUT"]) }), { direction: MARK }],
    ["unknown key", z.object({ a: z.string() }).strict(), { a: "x", [`extra_${MARK}`]: 1 }],
    ["literal", z.object({ v: z.literal("yes") }), { v: MARK }],
    ["type", z.object({ n: z.number() }), { n: MARK }],
    ["regex", z.object({ id: z.string().regex(/^[a-z]+$/) }), { id: MARK }],
    ["email", z.object({ e: z.string().email() }), { e: MARK }],
  ])("%s", async (_n, schema, body) => {
    const r = await appWith(schema).inject({ method: "POST", url: "/t", payload: body });
    expect(r.statusCode).toBe(422);
    expect(r.body).not.toContain(MARK);
    expect(r.json().error).toBe("invalid_request");
  });

  it("still tells the client what IS allowed", async () => {
    const r = await appWith(z.object({ direction: z.enum(["INPUT", "OUTPUT"]) })).inject({ method: "POST", url: "/t", payload: { direction: MARK } });
    expect(r.json().issues[0]).toEqual({ path: "direction", message: "Invalid value. Expected one of: INPUT, OUTPUT" });
  });
});
