"use client";
import { useState } from "react";
import { Shell } from "@/components/dashboard/Shell";
import { PolicyEditor } from "@/components/policies/PolicyEditor";
import { Button, Card, Loading, Notice } from "@/components/ui/primitives";
import { useApi } from "@/hooks/useApi";
import { api, describeError } from "@/lib/api/client";
import { formatTime } from "@/lib/utils/format";
import type { PolicyDetail, PolicyRuleDto, PolicySummary } from "@/types/api";

type Editing = { policyId: string | null; rules: PolicyRuleDto[] } | null;

export default function PoliciesPage() {
  const list = useApi<{ policies: PolicySummary[] }>("policies");
  const [editing, setEditing] = useState<Editing>(null);
  const [message, setMessage] = useState<{ kind: "error" | "success"; text: string } | null>(null);

  const edit = async (policyId: string) => {
    setMessage(null);
    try { const d = await api.get<PolicyDetail>(`policies/${encodeURIComponent(policyId)}`); setEditing({ policyId, rules: d.rules }); }
    catch (e) { setMessage({ kind: "error", text: describeError(e) }); }
  };

  const save = async (policyId: string, rules: PolicyRuleDto[]) => {
    if (editing?.policyId === null) await api.post("policies", { policy_id: policyId, rules });
    else await api.put(`policies/${encodeURIComponent(policyId)}`, { rules });
    setEditing(null); setMessage({ kind: "success", text: `Policy "${policyId}" saved and activated.` }); list.reload();
  };

  const deactivate = async (policyId: string) => {
    if (!window.confirm(`Deactivate policy "${policyId}"? Requests will fall back to the baseline for its entities.`)) return;
    try { await api.del(`policies/${encodeURIComponent(policyId)}`); setMessage({ kind: "success", text: `Policy "${policyId}" deactivated.` }); list.reload(); }
    catch (e) { setMessage({ kind: "error", text: describeError(e) }); }
  };

  const active = list.data?.policies.filter((p) => p.active) ?? [];
  const history = list.data?.policies.filter((p) => !p.active) ?? [];

  return (
    <Shell title="Policies">
      {message && <Notice kind={message.kind}>{message.text}</Notice>}
      {editing ? (
        <Card title={editing.policyId === null ? "New policy" : `Edit ${editing.policyId} (creates a new version)`}>
          <PolicyEditor policyId={editing.policyId} initialRules={editing.rules} onSubmit={save} onCancel={() => setEditing(null)} />
        </Card>
      ) : (
        <>
          <Card title="Active policies" action={<Button onClick={() => { setMessage(null); setEditing({ policyId: null, rules: [] }); }}>New policy</Button>}>
            <p className="mb-3 text-xs text-slate-500">All active policies apply together; the most restrictive matching rule wins. With none active, the severity baseline applies (CRITICAL blocks, HIGH redacts, MEDIUM masks).</p>
            {list.loading && !list.data && <Loading />}
            {list.error && <Notice>{list.error}</Notice>}
            {list.data && active.length === 0 && <p className="text-sm text-slate-500">No active policies.</p>}
            <ul className="divide-y divide-slate-100 dark:divide-slate-800">
              {active.map((p) => (
                <li key={p.policy_id} className="flex flex-wrap items-center justify-between gap-2 py-2 text-sm">
                  <div><span className="font-medium">{p.policy_id}</span> <span className="text-xs text-slate-500">v{p.version} · {p.rule_count} rule{p.rule_count === 1 ? "" : "s"} · {formatTime(p.created_at)}</span></div>
                  <div className="flex gap-2"><Button variant="secondary" onClick={() => edit(p.policy_id)}>Edit</Button><Button variant="danger" onClick={() => deactivate(p.policy_id)}>Deactivate</Button></div>
                </li>
              ))}
            </ul>
          </Card>
          {history.length > 0 && (
            <Card title="Version history">
              <ul className="space-y-1 text-xs text-slate-600 dark:text-slate-400">{history.map((p) => <li key={`${p.policy_id}-${p.version}`}>{p.policy_id} v{p.version} · {p.rule_count} rules · {formatTime(p.created_at)}</li>)}</ul>
            </Card>
          )}
        </>
      )}
    </Shell>
  );
}
