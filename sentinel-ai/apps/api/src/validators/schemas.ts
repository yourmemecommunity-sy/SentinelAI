import { z } from "zod";
import { ACTIONS, DIRECTIONS, ENTITY_TYPES, NEVER_ALLOW_ENTITIES, SEVERITIES } from "@sentinelai/shared-types";

const neverAllow: ReadonlySet<string> = new Set(NEVER_ALLOW_ENTITIES);

/**
 * True when a string can be stored as PostgreSQL text and shown safely: no control characters (PostgreSQL rejects NUL
 * outright) and well-formed Unicode (a lone UTF-16 surrogate cannot be encoded as UTF-8). Found by fuzzing: a team named
 * "\u0000..." reached the database and came back as HTTP 500.
 */
const CONTROL = /[\u0000-\u001F\u007F]/;
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
export function isCleanText(s: string): boolean {
  return !CONTROL.test(s) && !LONE_SURROGATE.test(s);
}

/** A human-entered name that is persisted (team, API key, organization). */
export const displayName = (max: number) =>
  z.string().trim().min(1).max(max).refine(isCleanText, "must not contain control characters or malformed Unicode");
const HHMM = /^(?:[01]\d|2[0-3]):[0-5]\d$/;

export const RuleScopeSchema = z.object({
  users: z.array(z.string().max(256)).max(100).optional(),
  teams: z.array(z.string().max(256)).max(100).optional(),
  applications: z.array(z.string().max(256)).max(100).optional(),
  providers: z.array(z.string().max(64)).max(20).optional(),
  models: z.array(z.string().max(128)).max(100).optional(),
  environments: z.array(z.string().max(64)).max(20).optional(),
  ip_cidrs: z.array(z.string().max(64)).max(50).optional(),
  time_window_utc: z.object({ start: z.string().regex(HHMM), end: z.string().regex(HHMM) }).strict().optional(),
  directions: z.array(z.enum(DIRECTIONS)).optional(),
}).strict();

export const PolicyRuleSchema = z.object({
  entity: z.enum(ENTITY_TYPES),
  action: z.enum(ACTIONS),
  severity: z.enum(SEVERITIES).optional(),
  min_confidence: z.number().min(0).max(1).optional(),
  scope: RuleScopeSchema.optional(),
}).strict().superRefine((r, ctx) => {
  if (r.action === "ALLOW" && (neverAllow.has(r.entity) || r.severity === "CRITICAL")) {
    ctx.addIssue({ code: "custom", message: `${r.entity} cannot be ALLOWed by policy (sanitize or block instead)` });
  }
});

export const PolicyBodySchema = z.object({
  policy_id: z.string().min(1).max(128).regex(/^[A-Za-z0-9][A-Za-z0-9._-]*$/),
  rules: z.array(PolicyRuleSchema).max(500),
}).strict();
export const PolicyUpdateSchema = z.object({ rules: z.array(PolicyRuleSchema).max(500) }).strict();

export const ContextSchema = z.object({
  application: z.string().max(256).optional(),
  team: z.string().max(256).optional(),
  environment: z.string().max(64).optional(),
  model: z.string().max(128).optional(),
}).strict();

export const ScanBodySchema = z.object({
  text: z.string(),
  direction: z.enum(DIRECTIONS).default("INPUT"),
  context: ContextSchema.optional(),
}).strict();

export const MessageSchema = z.object({ role: z.enum(["system", "user", "assistant"]), content: z.string().min(1) }).strict();

const ProviderId = z.string().regex(/^[a-z][a-z0-9_-]{1,31}$/);
const ModelId = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,99}$/);

export const ChatBodySchema = z.object({
  provider: ProviderId, model: ModelId.optional(),
  messages: z.array(MessageSchema).min(1).max(100),
  application: z.string().max(256).optional(), team: z.string().max(256).optional(), environment: z.string().max(64).optional(),
  max_output_tokens: z.number().int().min(1).max(32_768).optional(), temperature: z.number().min(0).max(2).optional(),
  /** Names a token-vault session: tokens minted by TOKENIZE policies in one call can be hydrated in the reply (and in later calls with the same id). */
  session_id: z.string().regex(/^[A-Za-z0-9_.:@-]{1,128}$/).optional(),
  /** Set false to receive tokens un-hydrated. */
  hydrate: z.boolean().optional(),
}).strict();

export const StreamBodySchema = ChatBodySchema.extend({
  /** "holdback" (default) streams with a look-ahead scan; "buffered" releases nothing until the whole reply has been scanned. */
  mode: z.enum(["holdback", "buffered"]).optional(),
}).strict();

export const GenerateBodySchema = z.object({
  provider: ProviderId, model: ModelId.optional(), prompt: z.string().min(1),
  application: z.string().max(256).optional(), team: z.string().max(256).optional(), environment: z.string().max(64).optional(),
  max_output_tokens: z.number().int().min(1).max(32_768).optional(), temperature: z.number().min(0).max(2).optional(),
}).strict();

export const EventsQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(200).default(50),
  risk_level: z.enum(SEVERITIES).optional(),
  action: z.enum(ACTIONS).optional(),
  event_type: z.enum(["scan", "ai_request", "ai_response", "fail_closed", "file_scan"]).optional(),
  before: z.string().datetime().optional(),
}).strict();

export const UsageQuerySchema = z.object({ days: z.coerce.number().int().min(1).max(366).default(30) }).strict();
