import { describe, expect, it } from "vitest";
import { loadConfig } from "../../src/config/env.js";

/** A complete, valid production environment. Each test removes or breaks one thing. */
const PROD = {
  NODE_ENV: "production",
  API_KEY_HASH_PEPPER: "a".repeat(20) + "b".repeat(20),
  JWT_ACCESS_SECRET: "c".repeat(20) + "d".repeat(20),
  SECURITY_ENGINE_TOKEN: "e".repeat(24),
  DATABASE_URL: "postgresql://sentinel_api:pw@postgres:5432/sentinel",
  API_CORS_ORIGINS: "https://dash.example.test",
};

describe("configuration: production fails closed", () => {
  it("a complete production environment loads", () => {
    const c = loadConfig(PROD);
    expect(c.nodeEnv).toBe("production");
    expect(c.signupEnabled).toBe(false);                         // self-service signup is opt-in in production
  });

  it.each([
    ["missing pepper", { API_KEY_HASH_PEPPER: undefined }],
    ["short pepper", { API_KEY_HASH_PEPPER: "x".repeat(31) }],
    ["placeholder pepper", { API_KEY_HASH_PEPPER: "change-me-generate-with-openssl-rand-hex-32" }],
    ["missing engine token", { SECURITY_ENGINE_TOKEN: undefined }],
    ["short engine token", { SECURITY_ENGINE_TOKEN: "short" }],
    ["missing DATABASE_URL", { DATABASE_URL: undefined }],
    ["JWT secret equal to the pepper", { JWT_ACCESS_SECRET: PROD.API_KEY_HASH_PEPPER }],
    ["short JWT secret", { JWT_ACCESS_SECRET: "y".repeat(10) }],
    ["wildcard CORS", { API_CORS_ORIGINS: "*" }],
    ["vault without a token", { VAULT_URL: "http://token-vault:8004" }],
    ["document scanner without a token", { DOCUMENT_SCANNER_URL: "http://document-scanner:8003" }],
  ])("refuses to start: %s", (_name, over) => {
    const env = { ...PROD, ...over } as Record<string, string | undefined>;
    for (const [k, v] of Object.entries(env)) if (v === undefined) delete env[k];
    expect(() => loadConfig(env as NodeJS.ProcessEnv)).toThrow();
  });
});

describe("configuration: an empty variable means unset", () => {
  it("empty optional settings are ignored instead of rejected (compose/k8s pass unset values as \"\")", () => {
    const c = loadConfig({ ...PROD, OLLAMA_BASE_URL: "", OLLAMA_MODEL: "", GEMINI_API_KEY: "", OPENAI_API_KEY: "  ", ANTHROPIC_API_KEY: "" });
    expect(c.ollama).toBeUndefined();
    expect(c.geminiApiKey).toBeUndefined();
    expect(c.openaiApiKey).toBeUndefined();
    expect(c.anthropicApiKey).toBeUndefined();
  });

  it("an EMPTY required secret is still missing, so production still refuses to start", () => {
    for (const k of ["API_KEY_HASH_PEPPER", "SECURITY_ENGINE_TOKEN", "DATABASE_URL"]) {
      expect(() => loadConfig({ ...PROD, [k]: "" }), k).toThrow();
    }
    expect(() => loadConfig({ ...PROD, VAULT_URL: "http://token-vault:8004", VAULT_TOKEN: "" })).toThrow();
  });

  it("a genuinely invalid optional value is still rejected", () => {
    expect(() => loadConfig({ ...PROD, OLLAMA_BASE_URL: "not a url", OLLAMA_MODEL: "m" })).toThrow();
  });

  it("Ollama is registered only when both base URL and model are set", () => {
    expect(loadConfig({ ...PROD, OLLAMA_BASE_URL: "http://ollama:11434", OLLAMA_MODEL: "" }).ollama).toBeUndefined();
    expect(loadConfig({ ...PROD, OLLAMA_BASE_URL: "http://ollama:11434", OLLAMA_MODEL: "qwen2:0.5b" }).ollama).toEqual({ baseUrl: "http://ollama:11434", model: "qwen2:0.5b" });
  });
});
