import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { MAX_LOOKUPS, MAX_TOKEN_LEN, TokenWindow, WINDOW_CHARS, findTokens, hydrateText, isTokenPrefix, type TokenResolver } from "../../src/streaming/tokenWindow.js";

const VALUES = new Map([
  ["[TOK_NAME_1]", "John Doe"], ["[TOK_EMAIL_1]", "john.doe@example.com"], ["[TOK_PHONE_1]", "+1 415 555 0132"], ["[TOK_NAME_2]", "Ana [TOK_NAME_1] Ruiz"],
]);

function stub(values = VALUES) {
  const calls: string[][] = [];
  let fail = false;
  const resolver: TokenResolver = async (tokens) => {
    calls.push([...tokens]);
    if (fail) throw new Error("vault down");
    return new Map(tokens.filter((t) => values.has(t)).map((t) => [t, values.get(t)!]));
  };
  return { resolver, calls, setFail: (v: boolean) => { fail = v; } };
}

const TOKEN_RE = /\[TOK_[A-Z](?:[A-Z_]{0,30}[A-Z])?_[0-9]{1,6}\]/g;
const expected = (text: string, values = VALUES) => text.replace(TOKEN_RE, (t) => values.get(t) ?? t);

async function run(chunks: string[], s = stub(), opts = {}) {
  const w = new TokenWindow(s.resolver, opts);
  const out: string[] = [];
  let maxHeld = 0;
  for (const c of chunks) { out.push(await w.push(c)); maxHeld = Math.max(maxHeld, w.held); }
  out.push(await w.flush());
  return { text: out.join(""), w, s, maxHeld };
}

const TEXT = "Hello [TOK_NAME_1], mail [TOK_EMAIL_1] or call [TOK_PHONE_1]. Unknown [TOK_NAME_9] stays, [not a token] stays, [TOK_x] and [TOK_NAME_] stay; [TOK_NAME_2] keeps its inner text. Done [TOK_NAME_1]";

describe("TokenWindow: tokens split across network chunks", () => {
  it("one chunk", async () => {
    const r = await run([TEXT]);
    expect(r.text).toBe(expected(TEXT));
    expect(r.text).toContain("John Doe"); expect(r.text).toContain("[TOK_NAME_9]"); expect(r.text).toContain("[not a token]");
  });

  it("every possible two-way split gives the same result", async () => {
    const want = expected(TEXT);
    for (let i = 0; i <= TEXT.length; i++) expect((await run([TEXT.slice(0, i), TEXT.slice(i)])).text, `split at ${i}`).toBe(want);
  });

  it("one character at a time", async () => {
    const r = await run([...TEXT]);
    expect(r.text).toBe(expected(TEXT));
    expect(r.w.held).toBe(0);
  });

  it("random multi-way splits; never more than a partial token is held, always inside the 50-character window", async () => {
    let seed = 987654321;
    const rnd = () => { seed = (seed * 1664525 + 1013904223) >>> 0; return seed / 2 ** 32; };
    const want = expected(TEXT);
    for (let n = 0; n < 500; n++) {
      const cuts = [...new Set(Array.from({ length: 1 + Math.floor(rnd() * 12) }, () => 1 + Math.floor(rnd() * (TEXT.length - 1))))].sort((a, b) => a - b);
      const chunks = [0, ...cuts].map((a, i, all) => TEXT.slice(a, all[i + 1] ?? TEXT.length));
      const r = await run(chunks);
      expect(r.text).toBe(want);
      expect(r.maxHeld).toBeLessThan(MAX_TOKEN_LEN);
      expect(r.maxHeld).toBeLessThanOrEqual(WINDOW_CHARS);
    }
  });

  it("releases text immediately; only a trailing partial token is held", async () => {
    const s = stub();
    const w = new TokenWindow(s.resolver);
    expect(await w.push("Hello wor")).toBe("Hello wor");
    expect(await w.push("ld [TOK_NA")).toBe("ld ");
    expect(w.held).toBe("[TOK_NA".length);
    expect(await w.push("ME_1] and")).toBe("John Doe and");
    expect(w.held).toBe(0);
  });

  it("a bracket that cannot become a token is never held back", async () => {
    for (const tail of ["see [1]", "list [x", "array[0", "[TOKEN", "a [ b"]) {
      const w = new TokenWindow(stub().resolver);
      expect(await w.push(tail)).toBe(tail);
      expect(w.held).toBe(0);
    }
  });

  it("an unfinished token at the end is flushed literally", async () => {
    expect((await run(["value [TOK_NAME_"])).text).toBe("value [TOK_NAME_");
  });

  it("hydrated values are not rescanned (a value that looks like a token stays literal)", async () => {
    expect((await run(["[TOK_NAME_2] and [TOK_NAME_", "1]"])).text).toBe("Ana [TOK_NAME_1] Ruiz and John Doe");
  });

  it("unicode and emoji survive every split", async () => {
    const text = "Grüße 🙂 [TOK_NAME_1] — 山田 [TOK_EMAIL_1] ✓";
    for (let i = 0; i <= text.length; i++) expect((await run([text.slice(0, i), text.slice(i)])).text).toBe(expected(text));
  });

  it("the fast path: text with no bracket never touches the resolver", async () => {
    const r = await run(["plain ", "", "text"]);
    expect(r.text).toBe("plain text");
    expect(r.s.calls).toEqual([]);
  });
});

describe("TokenWindow: lookups", () => {
  it("looks each token up once per stream (positive and negative caching)", async () => {
    const a = await run(["[TOK_NAME_1] ", "[TOK_NAME_1] [TOK_EMAIL_1] ", "[TOK_NAME_1] [TOK_EMAIL_1]"]);
    expect(a.s.calls.flat().sort()).toEqual(["[TOK_EMAIL_1]", "[TOK_NAME_1]"]);
    const b = await run(["[TOK_NAME_9] ", "[TOK_NAME_9] ", "[TOK_NAME_9]"]);
    expect(b.s.calls).toHaveLength(1);
  });

  it("a chunk with several tokens costs ONE resolver call", async () => {
    const r = await run(["[TOK_NAME_1] [TOK_EMAIL_1] [TOK_PHONE_1] [TOK_NAME_9]"]);
    expect(r.s.calls).toHaveLength(1);
    expect(r.s.calls[0]).toHaveLength(4);
  });

  it("a model guessing many tokens cannot amplify into the vault", async () => {
    const guesses = Array.from({ length: MAX_LOOKUPS + 200 }, (_, i) => `[TOK_NAME_${i + 1}]`).join(" ");
    const r = await run([guesses]);
    expect(r.s.calls.flat()).toHaveLength(MAX_LOOKUPS);
    expect(r.text.split("[TOK_NAME_").length - 1).toBeGreaterThanOrEqual(200);
  });
});

describe("TokenWindow: vault outage and abort", () => {
  it("degrades to un-hydrated tokens (no plaintext, no exception), flags it, and recovers once the vault is back", async () => {
    const s = stub();
    s.setFail(true);
    const w = new TokenWindow(s.resolver);
    expect(await w.push("Hi [TOK_NAME_1] ")).toBe("Hi [TOK_NAME_1] ");
    expect(w.degraded).toBe(true);
    s.setFail(false);
    expect(await w.push("and [TOK_NAME_1]")).toBe("and John Doe");         // failures are not cached
  });

  it("a slow resolver holds only that push; text already released is unaffected", async () => {
    const w = new TokenWindow(() => new Promise<Map<string, string>>(() => undefined), {});
    // pushes without tokens never wait on the resolver
    expect(await w.push("no tokens here")).toBe("no tokens here");
  });

  it("after abort it stops resolving and drops what it holds", async () => {
    const ctl = new AbortController();
    const s = stub();
    const w = new TokenWindow(s.resolver, { signal: ctl.signal });
    expect(await w.push("start [TOK_NA")).toBe("start ");
    ctl.abort();
    expect(await w.push("ME_1] [TOK_EMAIL_1]")).toBe("");
    expect(w.held).toBe(0);
    expect(s.calls).toEqual([]);
  });

  it("an abort that lands while the vault call is in flight releases nothing", async () => {
    const ctl = new AbortController();
    const w = new TokenWindow(async (t) => { ctl.abort(); return new Map(t.map((x) => [x, "PLAINTEXT"])); }, { signal: ctl.signal });
    expect(await w.push("hi [TOK_NAME_1]")).toBe("");
  });
});

describe("token grammar helpers", () => {
  it("findTokens and isTokenPrefix", () => {
    expect(findTokens("a [TOK_NAME_1] b [TOK_NAME_1] [TOK_EMAIL_2] [TOK_x_1]")).toEqual(["[TOK_NAME_1]", "[TOK_EMAIL_2]"]);
    expect(findTokens("nothing")).toEqual([]);
    const token = "[TOK_DATE_OF_BIRTH_123]";
    for (let i = 1; i < token.length; i++) expect(isTokenPrefix(token.slice(0, i)), token.slice(0, i)).toBe(true);
    for (const t of ["[X", "[TOKEN", "[TOK-", "[tok_", "[TOK_name", "[[", "[ TOK", "[TOK_A B"]) expect(isTokenPrefix(t), t).toBe(false);
    expect(isTokenPrefix("[TOK_" + "A".repeat(60))).toBe(false);
  });

  it("hydrateText hydrates a whole message with one lookup, and degrades safely", async () => {
    const s = stub();
    expect(await hydrateText("Dear [TOK_NAME_1], [TOK_NAME_1] and [TOK_EMAIL_1] [TOK_NAME_9]", s.resolver)).toEqual({ text: "Dear John Doe, John Doe and john.doe@example.com [TOK_NAME_9]", degraded: false });
    expect(s.calls).toHaveLength(1);
    expect(await hydrateText("no tokens", s.resolver)).toEqual({ text: "no tokens", degraded: false });
    expect(s.calls).toHaveLength(1);
    s.setFail(true);
    expect(await hydrateText("Dear [TOK_NAME_1]", s.resolver)).toEqual({ text: "Dear [TOK_NAME_1]", degraded: true });
  });
});

describe("cross-language: this window and the Python vault agree on the token grammar", () => {
  const py = readFileSync(resolve(dirname(fileURLToPath(import.meta.url)), "../../../../services/token-vault/app/tokens.py"), "utf-8");
  const pyStr = (name: string): string => new RegExp(`${name}\\s*=\\s*r?"([^"]*)"`).exec(py)![1]!;

  it("type pattern, token length and prefix grammar are identical", () => {
    const typePattern = pyStr("TYPE_PATTERN");
    expect(typePattern).toBe("[A-Z](?:[A-Z_]{0,30}[A-Z])?");
    expect(new RegExp(`^\\[TOK_${typePattern}_[0-9]{1,6}\\]$`).source).toBe(new RegExp("^" + String.raw`\[TOK_[A-Z](?:[A-Z_]{0,30}[A-Z])?_[0-9]{1,6}\]` + "$").source);
    expect(/MAX_TOKEN_LEN\s*=\s*45\b/.test(py)).toBe(true);
    expect(MAX_TOKEN_LEN).toBe(45);
    expect(/_PREFIX\s*=\s*re\.compile\(r"\\\[\(\?:T\|TO\|TOK\|TOK_\[A-Z0-9_\]\{0,39\}\)\?"\)/.test(py)).toBe(true);
  });

  it("the same probe strings are accepted/rejected by the TS grammar as the Python tests expect", () => {
    for (const ok of ["[TOK_NAME_1]", "[TOK_DATE_OF_BIRTH_42]", "[TOK_A_1]"]) expect(findTokens(ok)).toEqual([ok]);
    for (const bad of ["[TOK_name_1]", "[TOK_NAME_]", "[TOK__1]", "[TOK_NAME_1234567]", "[TOK_NAME1_1]", "[tok_NAME_1]", "[TOK_NAME_-1]", "[TOK_ NAME_1]"]) expect(findTokens(bad)).toEqual([]);
  });
});
