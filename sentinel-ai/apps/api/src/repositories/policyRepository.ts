import type { Policy, PolicyRule } from "@sentinelai/shared-types";
import type { TenantDb } from "../db/tenantDb.js";

export const BASELINE_POLICY_ID = "sentinelai-baseline";

export interface PolicySummary { policy_id: string; version: number; active: boolean; rule_count: number; created_at: string }

export interface PolicyRepository {
  /**
   * The organization's effective policy: the union of all ACTIVE policies' rules (deny-overrides makes the union
   * well-defined). Returns undefined when none are active (the engine then applies its baseline). Throws on failure.
   */
  getEffectivePolicy(orgId: string): Promise<Policy | undefined>;
  /**
   * The exact policy an event was decided with, rebuilt from its recorded id ("a@3+b@2" or the baseline id) and the
   * immutable policy versions. Undefined for the baseline. Null if a recorded version no longer exists.
   */
  getRecorded(orgId: string, recordedPolicyId: string): Promise<Policy | undefined | null>;
  /** Organization switch for the external LLM judge (organizations.external_judge). */
  getExternalJudge(orgId: string): Promise<boolean>;
  setExternalJudge(orgId: string, enabled: boolean): Promise<void>;
  list(orgId: string): Promise<PolicySummary[]>;
  get(orgId: string, policyId: string): Promise<{ policy_id: string; version: number; active: boolean; rules: PolicyRule[] } | null>;
  /** Creates the next immutable version and makes it the only active one. */
  createVersion(orgId: string, policyId: string, rules: PolicyRule[], createdBy: string | null): Promise<number>;
  /** Deactivates every version of the policy. Returns false if there was none. */
  deactivate(orgId: string, policyId: string): Promise<boolean>;
}

type RuleRow = { entity: string; action: string; severity: string | null; min_confidence: number; scope: unknown };
const toRule = (r: RuleRow): PolicyRule => ({
  entity: r.entity as PolicyRule["entity"], action: r.action as PolicyRule["action"],
  ...(r.severity ? { severity: r.severity as NonNullable<PolicyRule["severity"]> } : {}),
  ...(r.min_confidence > 0 ? { min_confidence: r.min_confidence } : {}),
  ...(r.scope ? { scope: r.scope as NonNullable<PolicyRule["scope"]> } : {}),
});

export class PgPolicyRepository implements PolicyRepository {
  constructor(private readonly db: TenantDb) {}

  getEffectivePolicy(orgId: string): Promise<Policy | undefined> {
    return this.db.withTenant(orgId, async (q) => {
      const { rows } = await q.query<RuleRow & { policy_id: string; version: number }>(
        `SELECT p.policy_id, p.version, r.entity, r.action, r.severity, r.min_confidence, r.scope
         FROM policies p LEFT JOIN policy_rules r ON r.policy_pk = p.id
         WHERE p.active ORDER BY p.policy_id, r.position`);
      const judge = (await q.query<{ external_judge: boolean }>("SELECT external_judge FROM organizations")).rows[0]?.external_judge ?? true;
      if (rows.length === 0) {
        // No active policy: the engine applies its baseline. Only send one if the judge must be switched off.
        return judge ? undefined : { policy_id: BASELINE_POLICY_ID, organization_id: orgId, rules: [], external_judge: false };
      }
      const ids = [...new Set(rows.map((r) => `${r.policy_id}@${r.version}`))];
      return { policy_id: ids.join("+"), organization_id: orgId, rules: rows.filter((r) => r.entity).map(toRule),
        ...(judge ? {} : { external_judge: false }) };
    });
  }

  getRecorded(orgId: string, recordedPolicyId: string): Promise<Policy | undefined | null> {
    if (recordedPolicyId === BASELINE_POLICY_ID) return Promise.resolve(undefined);
    const parts = recordedPolicyId.split("+").map((s) => /^(.+)@(\d+)$/.exec(s));
    if (parts.some((m) => m === null)) return Promise.resolve(null);
    return this.db.withTenant(orgId, async (q) => {
      const rules: PolicyRule[] = [];
      for (const m of parts as RegExpExecArray[]) {
        const head = (await q.query<{ id: string }>("SELECT id FROM policies WHERE policy_id = $1 AND version = $2",
          [m[1], Number(m[2])])).rows[0];
        if (!head) return null;
        rules.push(...(await q.query<RuleRow>(
          "SELECT entity, action, severity, min_confidence, scope FROM policy_rules WHERE policy_pk = $1 ORDER BY position",
          [head.id])).rows.map(toRule));
      }
      return { policy_id: recordedPolicyId, organization_id: orgId, rules };
    });
  }

  getExternalJudge(orgId: string): Promise<boolean> {
    return this.db.withTenant(orgId, async (q) =>
      (await q.query<{ external_judge: boolean }>("SELECT external_judge FROM organizations")).rows[0]?.external_judge ?? true);
  }

  setExternalJudge(orgId: string, enabled: boolean): Promise<void> {
    return this.db.withTenant(orgId, async (q) => { await q.query("UPDATE organizations SET external_judge = $1", [enabled]); });
  }

  list(orgId: string): Promise<PolicySummary[]> {
    return this.db.withTenant(orgId, async (q) => (await q.query<{ policy_id: string; version: number; active: boolean; rule_count: number; created_at: Date }>(
      `SELECT p.policy_id, p.version, p.active, (SELECT count(*)::int FROM policy_rules r WHERE r.policy_pk = p.id) AS rule_count, p.created_at
       FROM policies p ORDER BY p.policy_id, p.version DESC`)).rows
      .map((r) => ({ ...r, created_at: new Date(r.created_at).toISOString() })));
  }

  get(orgId: string, policyId: string) {
    return this.db.withTenant(orgId, async (q) => {
      const head = (await q.query<{ id: string; version: number; active: boolean }>(
        "SELECT id, version, active FROM policies WHERE policy_id = $1 ORDER BY active DESC, version DESC LIMIT 1", [policyId])).rows[0];
      if (!head) return null;
      const rules = (await q.query<RuleRow>(
        "SELECT entity, action, severity, min_confidence, scope FROM policy_rules WHERE policy_pk = $1 ORDER BY position", [head.id])).rows;
      return { policy_id: policyId, version: head.version, active: head.active, rules: rules.map(toRule) };
    });
  }

  createVersion(orgId: string, policyId: string, rules: PolicyRule[], createdBy: string | null): Promise<number> {
    return this.db.withTenant(orgId, async (q) => {
      const next = (await q.query<{ v: number }>("SELECT COALESCE(max(version),0)+1 AS v FROM policies WHERE policy_id = $1", [policyId])).rows[0]!.v;
      await q.query("UPDATE policies SET active = false WHERE policy_id = $1 AND active", [policyId]);
      const pk = (await q.query<{ id: string }>(
        "INSERT INTO policies (organization_id, policy_id, version, active, created_by) VALUES ($1,$2,$3,true,$4) RETURNING id",
        [orgId, policyId, next, createdBy])).rows[0]!.id;
      for (const [i, r] of rules.entries()) {
        await q.query(
          `INSERT INTO policy_rules (organization_id, policy_pk, position, entity, action, severity, min_confidence, scope)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
          [orgId, pk, i, r.entity, r.action, r.severity ?? null, r.min_confidence ?? 0, r.scope ? JSON.stringify(r.scope) : null]);
      }
      return next;
    });
  }

  deactivate(orgId: string, policyId: string): Promise<boolean> {
    return this.db.withTenant(orgId, async (q) => {
      const exists = (await q.query("SELECT 1 FROM policies WHERE policy_id = $1 LIMIT 1", [policyId])).rows.length > 0;
      await q.query("UPDATE policies SET active = false WHERE policy_id = $1 AND active", [policyId]);
      return exists;
    });
  }
}
