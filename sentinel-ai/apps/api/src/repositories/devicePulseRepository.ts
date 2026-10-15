import type { TenantDb } from "../db/tenantDb.js";

/** Who made a request: a user (JWT) or an API key. Rows are scoped to the organization AND the actor. */
export interface Actor { type: "user" | "api_key"; id: string }

export interface DevicePulseRequestRecord {
  id: string;
  organizationId: string;
  actor: Actor;
  diagnosticType: string;
  status: "completed" | "insufficient_data";
  findingCount: number;
  inputEventId: string | null;
  retentionDays: number;
}

export type FeedbackResult = "recorded" | "unknown_request" | "exists";

/** Every method throws when the store is unavailable; callers fail closed. */
export interface DevicePulseRepository {
  recordRequest(r: DevicePulseRequestRecord): Promise<void>;
  /** Only the actor that received an explanation may rate it, and only once, and only before it expires. */
  recordFeedback(orgId: string, actor: Actor, f: { requestId: string; rating: string; reasonCode: string | null }): Promise<FeedbackResult>;
  /** Erasure: deletes every request record of this actor and, by cascade, their feedback. */
  deleteActorData(orgId: string, actor: Actor): Promise<{ requests: number; feedback: number }>;
  /** Deletes expired rows of every organization. */
  purgeExpired(): Promise<number>;
}

export class PgDevicePulseRepository implements DevicePulseRepository {
  constructor(private readonly db: TenantDb) {}

  recordRequest(r: DevicePulseRequestRecord): Promise<void> {
    return this.db.withTenant(r.organizationId, async (q) => {
      await q.query(
        `INSERT INTO devicepulse_requests (id, organization_id, actor_type, actor_id, diagnostic_type, status, finding_count, input_event_id, expires_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8, now() + make_interval(days => $9::int))`,
        [r.id, r.organizationId, r.actor.type, r.actor.id, r.diagnosticType, r.status, r.findingCount, r.inputEventId, r.retentionDays]);
    });
  }

  recordFeedback(orgId: string, actor: Actor, f: { requestId: string; rating: string; reasonCode: string | null }): Promise<FeedbackResult> {
    return this.db.withTenant(orgId, async (q) => {
      const own = await q.query(
        "SELECT 1 FROM devicepulse_requests WHERE id = $1 AND actor_type = $2 AND actor_id = $3 AND expires_at > now()",
        [f.requestId, actor.type, actor.id]);
      if (own.rows.length === 0) return "unknown_request";
      const ins = await q.query(
        `INSERT INTO devicepulse_feedback (organization_id, request_id, rating, reason_code) VALUES ($1,$2,$3,$4)
         ON CONFLICT (request_id) DO NOTHING RETURNING id`, [orgId, f.requestId, f.rating, f.reasonCode]);
      return ins.rows.length === 1 ? "recorded" : "exists";
    });
  }

  deleteActorData(orgId: string, actor: Actor): Promise<{ requests: number; feedback: number }> {
    return this.db.withTenant(orgId, async (q) => {
      const fb = await q.query<{ n: number }>(
        `SELECT count(*)::int AS n FROM devicepulse_feedback f JOIN devicepulse_requests r ON r.id = f.request_id
         WHERE r.actor_type = $1 AND r.actor_id = $2`, [actor.type, actor.id]);
      const del = await q.query<{ n: number }>(
        `WITH d AS (DELETE FROM devicepulse_requests WHERE actor_type = $1 AND actor_id = $2 RETURNING 1) SELECT count(*)::int AS n FROM d`,
        [actor.type, actor.id]);
      return { requests: Number(del.rows[0]?.n ?? 0), feedback: Number(fb.rows[0]?.n ?? 0) };
    });
  }

  purgeExpired(): Promise<number> {
    return this.db.withoutTenant(async (q) => {
      const { rows } = await q.query<{ n: number }>("SELECT app_purge_devicepulse() AS n");
      return Number(rows[0]?.n ?? 0);
    });
  }
}

/** Test/dev double with the same semantics (organization + actor scoping, one rating per request). */
export class InMemoryDevicePulseRepository implements DevicePulseRepository {
  readonly requests: (DevicePulseRequestRecord & { expiresAt: number })[] = [];
  readonly feedback: { organizationId: string; requestId: string; rating: string; reasonCode: string | null }[] = [];
  fail = false;
  constructor(private readonly now: () => number = Date.now) {}

  private check(): void { if (this.fail) throw new Error("store unavailable"); }
  async recordRequest(r: DevicePulseRequestRecord): Promise<void> {
    this.check();
    this.requests.push({ ...r, expiresAt: this.now() + r.retentionDays * 86_400_000 });
  }
  async recordFeedback(orgId: string, actor: Actor, f: { requestId: string; rating: string; reasonCode: string | null }): Promise<FeedbackResult> {
    this.check();
    const own = this.requests.find((r) => r.id === f.requestId && r.organizationId === orgId && r.actor.type === actor.type
      && r.actor.id === actor.id && r.expiresAt > this.now());
    if (!own) return "unknown_request";
    if (this.feedback.some((x) => x.requestId === f.requestId)) return "exists";
    this.feedback.push({ organizationId: orgId, ...f });
    return "recorded";
  }
  async deleteActorData(orgId: string, actor: Actor): Promise<{ requests: number; feedback: number }> {
    this.check();
    const mine = new Set(this.requests.filter((r) => r.organizationId === orgId && r.actor.type === actor.type && r.actor.id === actor.id).map((r) => r.id));
    const fb = this.feedback.filter((f) => mine.has(f.requestId)).length;
    this.feedback.splice(0, this.feedback.length, ...this.feedback.filter((f) => !mine.has(f.requestId)));
    this.requests.splice(0, this.requests.length, ...this.requests.filter((r) => !mine.has(r.id)));
    return { requests: mine.size, feedback: fb };
  }
  async purgeExpired(): Promise<number> {
    this.check();
    const t = this.now();
    const expired = new Set(this.requests.filter((r) => r.expiresAt <= t).map((r) => r.id));
    this.feedback.splice(0, this.feedback.length, ...this.feedback.filter((f) => !expired.has(f.requestId)));
    this.requests.splice(0, this.requests.length, ...this.requests.filter((r) => !expired.has(r.id)));
    return expired.size;
  }
}
