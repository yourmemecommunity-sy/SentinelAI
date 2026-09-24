"use client";
import { ACTIONS, ENTITY_TYPES, SEVERITIES, type Action, type EntityType, type Severity } from "@sentinelai/shared-types";
import { useState } from "react";
import { Button, Field, Notice, Select } from "@/components/ui/primitives";
import { allowedActions, isAllowForbidden, validatePolicy } from "@/lib/validation/policy";
import type { PolicyRuleDto } from "@/types/api";

export interface PolicyEditorProps {
  /** null = creating a new policy (id is editable); string = new version of an existing policy. */
  policyId: string | null;
  initialRules: PolicyRuleDto[];
  onSubmit: (policyId: string, rules: PolicyRuleDto[]) => Promise<void>;
  onCancel: () => void;
}

const blank = (): PolicyRuleDto => ({ entity: "EMAIL", action: "MASK" });

export function PolicyEditor({ policyId, initialRules, onSubmit, onCancel }: PolicyEditorProps) {
  const [id, setId] = useState(policyId ?? "");
  const [rules, setRules] = useState<PolicyRuleDto[]>(initialRules.length ? initialRules : [blank()]);
  const [errors, setErrors] = useState<string[]>([]);
  const [saving, setSaving] = useState(false);
  const [serverError, setServerError] = useState<string | null>(null);

  const update = (i: number, patch: Partial<PolicyRuleDto>) => setRules((rs) => rs.map((r, j) => {
    if (j !== i) return r;
    const next = { ...r, ...patch };
    // If the new entity/severity forbids ALLOW, move off ALLOW to the safest option instead of leaving an invalid rule.
    if (next.action === "ALLOW" && isAllowForbidden(next.entity, next.severity)) next.action = "BLOCK";
    return next;
  }));

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setServerError(null);
    const problems = validatePolicy(id, rules, { requireId: policyId === null });
    setErrors(problems);
    if (problems.length) return;
    setSaving(true);
    try { await onSubmit(id, rules); } catch (err) { setServerError(err instanceof Error ? err.message : "Save failed."); } finally { setSaving(false); }
  };

  return (
    <form onSubmit={submit} className="space-y-4" noValidate>
      <Field id="policy-id" label="Policy id" value={id} onChange={(e) => setId(e.target.value)} disabled={policyId !== null} placeholder="engineering-policy" maxLength={128} />
      <p className="text-xs text-slate-500">
        Most restrictive matching rule wins. Anything without a rule falls back to the severity baseline. Credentials, payment cards and
        prompt-injection signals can be sanitized or blocked but never allowed.
      </p>
      <ul className="space-y-3">
        {rules.map((r, i) => (
          <li key={i} className="grid grid-cols-2 gap-2 rounded-md border border-slate-200 p-3 dark:border-slate-800 md:grid-cols-5">
            <Select id={`entity-${i}`} label="Entity" value={r.entity} onChange={(e) => update(i, { entity: e.target.value as EntityType })}>
              {ENTITY_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
            </Select>
            <Select id={`action-${i}`} label="Action" value={r.action} onChange={(e) => update(i, { action: e.target.value as Action })}>
              {ACTIONS.map((a) => {
                const blocked = !allowedActions(r.entity, r.severity).includes(a);
                return <option key={a} value={a} disabled={blocked}>{blocked ? `${a} (not permitted)` : a}</option>;
              })}
            </Select>
            <Select id={`severity-${i}`} label="Severity floor" value={r.severity ?? ""} onChange={(e) => update(i, e.target.value ? { severity: e.target.value as Severity } : { severity: undefined })}>
              <option value="">(none)</option>
              {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
            </Select>
            <Field id={`conf-${i}`} label="Min confidence" type="number" min={0} max={1} step={0.05} value={r.min_confidence ?? ""}
              onChange={(e) => update(i, e.target.value === "" ? { min_confidence: undefined } : { min_confidence: Number(e.target.value) })} />
            <div className="flex items-end"><Button type="button" variant="secondary" onClick={() => setRules((rs) => rs.filter((_, j) => j !== i))} aria-label={`Remove rule ${i + 1}`}>Remove</Button></div>
          </li>
        ))}
      </ul>
      <Button type="button" variant="secondary" onClick={() => setRules((rs) => [...rs, blank()])}>Add rule</Button>

      {errors.length > 0 && <Notice><ul className="list-disc pl-4">{errors.map((m) => <li key={m}>{m}</li>)}</ul></Notice>}
      {serverError && <Notice>{serverError}</Notice>}
      <div className="flex gap-2">
        <Button type="submit" disabled={saving}>{saving ? "Saving..." : policyId === null ? "Create policy" : "Save as new version"}</Button>
        <Button type="button" variant="secondary" onClick={onCancel}>Cancel</Button>
      </div>
    </form>
  );
}
