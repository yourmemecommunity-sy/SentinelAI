/**
 * Sliding-window token hydration for streamed text.
 *
 * Tokens look like `[TOK_<TYPE>_<n>]` (max 45 chars). A token can arrive split across network chunks (`...[TO` | `K_NAME_1]...`),
 * so the window holds back ONLY a trailing `[` that can still grow into a token (always < 45 chars, i.e. inside a 50-char window)
 * and releases everything else immediately. Complete tokens are resolved through an asynchronous callback (the token vault),
 * substituted, and flushed in the same call. Memory is O(window), never O(stream).
 *
 * Failure policy: if the resolver fails the token is left as-is (no plaintext is ever released on a guess) and `degraded` is set.
 * Hydrated values are never scanned again for tokens (a value that looks like a token stays literal).
 * Mirrors services/token-vault/app/detokenize.py; a cross-language test keeps the two in step.
 */
export const WINDOW_CHARS = 50;
export const MAX_TOKEN_LEN = 45;
const TOKEN_SRC = String.raw`\[TOK_[A-Z](?:[A-Z_]{0,30}[A-Z])?_[0-9]{1,6}\]`;
const TOKEN_PREFIX = /^\[(?:T|TO|TOK|TOK_[A-Z0-9_]{0,39})?$/;
export const MAX_LOOKUPS = 512;
const MAX_CACHE = 1024;

export const isTokenPrefix = (tail: string): boolean => tail.length < MAX_TOKEN_LEN && TOKEN_PREFIX.test(tail);
export const findTokens = (text: string): string[] => (text.includes("[TOK_") ? [...new Set(text.match(new RegExp(TOKEN_SRC, "g")) ?? [])] : []);

/** token -> plaintext for the tokens the session knows; unknown tokens are simply absent. May reject (vault down). */
export type TokenResolver = (tokens: string[]) => Promise<Map<string, string>>;

export interface TokenWindowOptions {
  /** Stop resolving (and drop buffered text) as soon as the client is gone. */
  signal?: AbortSignal | undefined;
  /** Distinct tokens one stream may ask about: a model emitting guessed tokens cannot amplify into vault load. */
  maxLookups?: number;
}

export class TokenWindow {
  private carry = "";
  private readonly cache = new Map<string, string | null>();   // null = looked up, not resolvable
  private lookups = 0;
  private readonly maxLookups: number;
  /** True once hydration was skipped for lack of the vault: some tokens were released un-hydrated (the safe direction). */
  degraded = false;

  constructor(private readonly resolve: TokenResolver, private readonly o: TokenWindowOptions = {}) {
    this.maxLookups = o.maxLookups ?? MAX_LOOKUPS;
  }

  /** Characters currently held back (always < MAX_TOKEN_LEN). */
  get held(): number { return this.carry.length; }

  /** Feed one chunk; returns the text that is now safe to flush to the client. */
  async push(chunk: string, final = false): Promise<string> {
    if (this.o.signal?.aborted) { this.carry = ""; return ""; }
    const text = this.carry + chunk;
    this.carry = "";
    if (!text.includes("[")) return text;                           // fast path: nothing token-like, nothing held

    const found = findTokens(text);
    const fresh = found.filter((t) => !this.cache.has(t));
    if (fresh.length > 0) {
      const room = Math.max(0, this.maxLookups - this.lookups);
      const ask = fresh.slice(0, room);
      for (const t of fresh.slice(room)) this.remember(t, null);
      if (ask.length > 0) {
        try {
          const got = await this.resolve(ask);
          if (this.o.signal?.aborted) return "";
          this.lookups += ask.length;
          for (const t of ask) this.remember(t, got.get(t) ?? null);
        } catch {
          this.degraded = true;                                     // not cached: a later chunk may succeed once the vault is back
        }
      }
    }

    const re = new RegExp(TOKEN_SRC, "g");
    const out: string[] = [];
    let pos = 0;
    for (let m = re.exec(text); m !== null; m = re.exec(text)) {
      out.push(text.slice(pos, m.index));
      out.push(this.cache.get(m[0]) ?? m[0]);
      pos = m.index + m[0].length;
    }
    let rest = text.slice(pos);
    if (!final) {
      const i = rest.lastIndexOf("[");
      if (i !== -1 && isTokenPrefix(rest.slice(i))) { this.carry = rest.slice(i); rest = rest.slice(0, i); }
    }
    out.push(rest);
    return out.join("");
  }

  /** End of stream: releases any held-back partial token literally. */
  flush(): Promise<string> { return this.push("", true); }

  private remember(token: string, value: string | null): void {
    this.cache.set(token, value);
    if (this.cache.size > MAX_CACHE) this.cache.delete(this.cache.keys().next().value as string);
  }
}

/** One-shot hydration of a whole message (non-streaming responses). Returns the text and whether hydration was skipped. */
export async function hydrateText(text: string, resolve: TokenResolver): Promise<{ text: string; degraded: boolean }> {
  const tokens = findTokens(text);
  if (tokens.length === 0) return { text, degraded: false };
  let values: Map<string, string>;
  try { values = await resolve(tokens.slice(0, MAX_LOOKUPS)); } catch { return { text, degraded: true }; }
  return { text: text.replace(new RegExp(TOKEN_SRC, "g"), (t) => values.get(t) ?? t), degraded: false };
}
