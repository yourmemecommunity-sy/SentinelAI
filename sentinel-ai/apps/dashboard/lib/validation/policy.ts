import { ACTIONS, ENTITY_TYPES, NEVER_ALLOW_ENTITIES, type Action, type EntityType, type Severity } from "@sentinelai/shared-types";
import type { PolicyRuleDto } from "@/types/api";

const NEVER_ALLOW: ReadonlySet<string> = new Set(NEVER_ALLOW_ENTITIES);

/** True when policy is not allowed to ALLOW this entity/severity (mirrors the gateway, engine and DB constraint). */
export function isAllowForbidden(entity: EntityType, severity: Severity | undefined): boolean {
  return NEVER_ALLOW.has(entity) || severity === "CRITICAL";
}

export function allowedActions(entity: EntityType, severity: Severity | undefined): readonly Action[] {
  return isAllowForbidden(entity, severity) ? ACTIONS.filter((a) => a !== "ALLOW") : ACTIONS;
}

const ID = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;

/** Client-side pre-validation for fast feedback. The gateway remains the authority and re-validates everything. */
export function validatePolicy(policyId: string, rules: PolicyRuleDto[], opts: { requireId?: boolean } = {}): string[] {
  const errors: string[] = [];
  if (opts.requireId !== false && (!policyId || policyId.length > 128 || !ID.test(policyId))) {
    errors.push("Policy id must start with a letter or digit and use only letters, digits, '.', '_' or '-' (max 128).");
  }
  if (rules.length > 500) errors.push("A policy can have at most 500 rules.");
  rules.forEach((r, i) => {
    const n = i + 1;
    if (!(ENTITY_TYPES as readonly string[]).includes(r.entity)) errors.push(`Rule ${n}: unknown entity.`);
    if (!(ACTIONS as readonly string[]).includes(r.action)) errors.push(`Rule ${n}: unknown action.`);
    if (r.action === "ALLOW" && isAllowForbidden(r.entity, r.severity)) {
      errors.push(`Rule ${n}: ${r.entity} cannot be ALLOWed (credentials, payment cards, threats and CRITICAL data must be sanitized or blocked).`);
    }
    if (r.min_confidence !== undefined && !(r.min_confidence >= 0 && r.min_confidence <= 1)) errors.push(`Rule ${n}: minimum confidence must be between 0 and 1.`);
  });
  return errors;
}
