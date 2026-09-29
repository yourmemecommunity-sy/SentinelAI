import { parseCredentialKeys, type CredentialKey } from "../security/credentialCipher.js";
import { z } from "zod";

const PLACEHOLDER = /change-?me|example|placeholder|secret123/i;

const Schema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  API_PORT: z.coerce.number().int().min(1).max(65535).default(4000),
  API_CORS_ORIGINS: z.string().default("http://localhost:3000"),
  API_KEY_HASH_PEPPER: z.string().min(1),
  SECURITY_ENGINE_URL: z.string().url().default("http://localhost:8001"),
  SECURITY_ENGINE_TOKEN: z.string().optional(),
  SECURITY_TIMEOUT_MS: z.coerce.number().int().min(50).max(30_000).default(2000),
  // Added per 1,000 characters scanned (the engine's NER cost grows with length). Must exceed the engine's own allowance.
  SECURITY_TIMEOUT_PER_KCHAR_MS: z.coerce.number().int().min(0).max(1000).default(60),
  DATABASE_URL: z.string().min(1).optional(),
  GEMINI_API_KEY: z.string().optional(),
  OPENAI_API_KEY: z.string().optional(),
  ANTHROPIC_API_KEY: z.string().optional(),
  OLLAMA_BASE_URL: z.string().url().optional(),
  OLLAMA_MODEL: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,99}$/).optional(),
  DOCUMENT_SCANNER_URL: z.string().url().optional(),
  DOCUMENT_SCANNER_TOKEN: z.string().optional(),
  DOCUMENT_SCANNER_TIMEOUT_MS: z.coerce.number().int().min(1000).max(300_000).default(60_000),
  MAX_FILE_BYTES: z.coerce.number().int().min(1024).max(100 * 1024 * 1024).default(20 * 1024 * 1024),
  VAULT_URL: z.string().url().optional(),
  VAULT_TOKEN: z.string().optional(),
  VAULT_TIMEOUT_MS: z.coerce.number().int().min(50).max(30_000).default(1000),
  STREAM_HOLDBACK_CHARS: z.coerce.number().int().min(0).max(10_000).default(256),
  STREAM_MIN_SEGMENT_CHARS: z.coerce.number().int().min(1).max(10_000).default(64),
  STREAM_IDLE_TIMEOUT_MS: z.coerce.number().int().min(1000).max(600_000).default(30_000),
  STREAM_MAX_DURATION_MS: z.coerce.number().int().min(1000).max(3_600_000).default(300_000),
  STREAM_MAX_OUTPUT_CHARS: z.coerce.number().int().min(1).max(500_000).default(200_000),
  STREAM_MAX_CONCURRENT: z.coerce.number().int().min(1).max(1000).default(10),
  MAX_INPUT_CHARS: z.coerce.number().int().min(1).max(500_000).default(200_000),
  RATE_LIMIT_PER_MINUTE: z.coerce.number().int().min(1).default(120),
  JWT_ACCESS_SECRET: z.string().optional(),
  ACCESS_TOKEN_TTL_SECONDS: z.coerce.number().int().min(60).max(3600).default(900),
  REFRESH_TOKEN_TTL_SECONDS: z.coerce.number().int().min(3600).max(90 * 86400).default(30 * 86400),
  SIGNUP_ENABLED: z.enum(["true", "false"]).optional(),
  PROVIDER_CREDENTIAL_KEYS: z.string().optional(),
});

export interface AppConfig {
  nodeEnv: "development" | "test" | "production";
  port: number;
  corsOrigins: string[];
  apiKeyPepper: string;
  securityEngineUrl: string;
  securityEngineToken: string | undefined;
  securityTimeoutMs: number;
  securityTimeoutPerKcharMs: number;
  databaseUrl: string | undefined;
  geminiApiKey: string | undefined;
  openaiApiKey: string | undefined;
  anthropicApiKey: string | undefined;
  /** Ollama is registered only when BOTH a base URL and a model are configured (operator config; never request-derived). */
  ollama: { baseUrl: string; model: string } | undefined;
  maxInputChars: number;
  /** File scanning is available only when a document scanner is configured. */
  documentScanner: { url: string; token: string | undefined; timeoutMs: number } | undefined;
  maxFileBytes: number;
  /** Token vault (reversible tokenization). Optional: without it replies are never hydrated. */
  vault: { url: string; token: string | undefined; timeoutMs: number } | undefined;
  stream: { holdBackChars: number; minSegmentChars: number; idleTimeoutMs: number; maxDurationMs: number; maxOutputChars: number; maxConcurrent: number };
  rateLimitPerMinute: number;
  jwtAccessSecret: string | undefined;
  accessTtlSeconds: number;
  refreshTtlSeconds: number;
  signupEnabled: boolean;
  /** Master keys for per-organization provider credentials (first = active). Absent: organizations cannot store credentials. */
  providerCredentialKeys: CredentialKey[] | undefined;
}

/** Parses and validates configuration. Production refuses to start with weak or missing security settings. */
export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  // An empty variable means "unset". Compose (`${X:-}`) and Kubernetes routinely pass optional settings as "", and treating
  // that as a value made the gateway reject `OLLAMA_BASE_URL=""` as an invalid URL and refuse to start. Required settings
  // are unaffected: an empty secret is still missing, so production still fails closed on it.
  const e = Schema.parse(Object.fromEntries(Object.entries(env).filter(([, v]) => v !== undefined && v.trim() !== "")));
  const production = e.NODE_ENV === "production";
  if (production) {
    if (e.API_KEY_HASH_PEPPER.length < 32 || PLACEHOLDER.test(e.API_KEY_HASH_PEPPER)) {
      throw new Error("API_KEY_HASH_PEPPER must be >= 32 chars and not a placeholder in production");
    }
    if (!e.SECURITY_ENGINE_TOKEN || e.SECURITY_ENGINE_TOKEN.length < 16) {
      throw new Error("SECURITY_ENGINE_TOKEN is required in production");
    }
    if (!e.DATABASE_URL) throw new Error("DATABASE_URL is required in production");
    if (e.DOCUMENT_SCANNER_URL && (!e.DOCUMENT_SCANNER_TOKEN || e.DOCUMENT_SCANNER_TOKEN.length < 16)) throw new Error("DOCUMENT_SCANNER_TOKEN is required in production when DOCUMENT_SCANNER_URL is set");
    if (e.VAULT_URL && (!e.VAULT_TOKEN || e.VAULT_TOKEN.length < 16)) throw new Error("VAULT_TOKEN is required in production when VAULT_URL is set");
    if (e.JWT_ACCESS_SECRET !== undefined && (e.JWT_ACCESS_SECRET.length < 32 || PLACEHOLDER.test(e.JWT_ACCESS_SECRET) || e.JWT_ACCESS_SECRET === e.API_KEY_HASH_PEPPER)) {
      throw new Error("JWT_ACCESS_SECRET must be >= 32 chars, not a placeholder, and different from API_KEY_HASH_PEPPER");
    }
    if (e.API_CORS_ORIGINS.split(",").some((o) => o.trim() === "*")) throw new Error("wildcard CORS origin is forbidden in production");
  }
  return {
    nodeEnv: e.NODE_ENV,
    port: e.API_PORT,
    corsOrigins: e.API_CORS_ORIGINS.split(",").map((o) => o.trim()).filter(Boolean),
    apiKeyPepper: e.API_KEY_HASH_PEPPER,
    securityEngineUrl: e.SECURITY_ENGINE_URL.replace(/\/+$/, ""),
    securityEngineToken: e.SECURITY_ENGINE_TOKEN,
    securityTimeoutMs: e.SECURITY_TIMEOUT_MS,
    securityTimeoutPerKcharMs: e.SECURITY_TIMEOUT_PER_KCHAR_MS,
    databaseUrl: e.DATABASE_URL,
    geminiApiKey: e.GEMINI_API_KEY || undefined,
    openaiApiKey: e.OPENAI_API_KEY || undefined,
    anthropicApiKey: e.ANTHROPIC_API_KEY || undefined,
    ollama: e.OLLAMA_BASE_URL && e.OLLAMA_MODEL ? { baseUrl: e.OLLAMA_BASE_URL, model: e.OLLAMA_MODEL } : undefined,
    maxInputChars: e.MAX_INPUT_CHARS,
    documentScanner: e.DOCUMENT_SCANNER_URL ? { url: e.DOCUMENT_SCANNER_URL.replace(/\/+$/, ""), token: e.DOCUMENT_SCANNER_TOKEN, timeoutMs: e.DOCUMENT_SCANNER_TIMEOUT_MS } : undefined,
    maxFileBytes: e.MAX_FILE_BYTES,
    vault: e.VAULT_URL ? { url: e.VAULT_URL.replace(/\/+$/, ""), token: e.VAULT_TOKEN, timeoutMs: e.VAULT_TIMEOUT_MS } : undefined,
    stream: {
      holdBackChars: e.STREAM_HOLDBACK_CHARS, minSegmentChars: e.STREAM_MIN_SEGMENT_CHARS, idleTimeoutMs: e.STREAM_IDLE_TIMEOUT_MS,
      maxDurationMs: e.STREAM_MAX_DURATION_MS, maxOutputChars: Math.min(e.STREAM_MAX_OUTPUT_CHARS, e.MAX_INPUT_CHARS), maxConcurrent: e.STREAM_MAX_CONCURRENT,
    },
    rateLimitPerMinute: e.RATE_LIMIT_PER_MINUTE,
    jwtAccessSecret: e.JWT_ACCESS_SECRET,
    accessTtlSeconds: e.ACCESS_TOKEN_TTL_SECONDS,
    refreshTtlSeconds: e.REFRESH_TOKEN_TTL_SECONDS,
    // Open self-service signup is opt-in in production, on by default elsewhere.
    signupEnabled: (e.SIGNUP_ENABLED ?? (production ? "false" : "true")) === "true",
    providerCredentialKeys: e.PROVIDER_CREDENTIAL_KEYS ? parseCredentialKeys(e.PROVIDER_CREDENTIAL_KEYS) : undefined,
  };
}
