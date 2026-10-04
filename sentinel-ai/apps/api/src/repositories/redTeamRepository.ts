import type { TenantDb } from "../db/tenantDb.js";

/** One red-team round (scripts/security/red_team.py). Counts only, plus a few synthetic, sanitized, truncated examples. */
export interface RedTeamRound {
  round: number;
  dataset_version: string;
  generator_model: string;
  engine_version: string;
  attacks: number;
  blocked: number;
  slipped: number;
  per_category: Record<string, { attacks: number; blocked: number; slipped: number; by_tier?: Record<string, number> | undefined }>;
  examples: { category: string; outcome: "blocked" | "slipped"; decided_by: string; text: string }[];
  cost_usd: number;
  ran_at?: string;
}

export interface RedTeamRepository {
  list(orgId: string, limit: number): Promise<RedTeamRound[]>;
  /** Append-only: a round number can be recorded once. Returns false if it already exists. */
  record(orgId: string, round: RedTeamRound): Promise<boolean>;
}

type Row = Omit<RedTeamRound, "ran_at" | "cost_usd"> & { ran_at: Date; cost_usd: number | string };

export class PgRedTeamRepository implements RedTeamRepository {
  constructor(private readonly db: TenantDb) {}

  list(orgId: string, limit: number): Promise<RedTeamRound[]> {
    return this.db.withTenant(orgId, async (q) => (await q.query<Row>(
      `SELECT round, dataset_version, generator_model, engine_version, attacks, blocked, slipped, per_category, examples, cost_usd, ran_at
       FROM red_team_rounds ORDER BY round DESC LIMIT $1`, [Math.min(Math.max(limit, 1), 200)])).rows
      .map((r) => ({ ...r, cost_usd: Number(r.cost_usd), ran_at: new Date(r.ran_at).toISOString() })));
  }

  record(orgId: string, r: RedTeamRound): Promise<boolean> {
    return this.db.withTenant(orgId, async (q) => {
      const res = await q.query(
        `INSERT INTO red_team_rounds (organization_id, round, dataset_version, generator_model, engine_version, attacks, blocked, slipped,
           per_category, examples, cost_usd)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT (organization_id, round) DO NOTHING RETURNING id`,
        [orgId, r.round, r.dataset_version, r.generator_model, r.engine_version, r.attacks, r.blocked, r.slipped,
          JSON.stringify(r.per_category), JSON.stringify(r.examples), r.cost_usd]);
      return res.rows.length > 0;
    });
  }
}

export class InMemoryRedTeamRepository implements RedTeamRepository {
  readonly rounds = new Map<string, RedTeamRound[]>();
  async list(orgId: string, limit: number) { return [...(this.rounds.get(orgId) ?? [])].sort((a, b) => b.round - a.round).slice(0, limit); }
  async record(orgId: string, r: RedTeamRound) {
    const list = this.rounds.get(orgId) ?? [];
    if (list.some((x) => x.round === r.round)) return false;
    list.push({ ...r, ran_at: new Date().toISOString() });
    this.rounds.set(orgId, list);
    return true;
  }
}
