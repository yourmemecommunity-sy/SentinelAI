"use client";
import { roleHas, type RoleName } from "@sentinelai/shared-types";
import { useState } from "react";
import { Shell } from "@/components/dashboard/Shell";
import { Button, Card, Chip, Field, Loading, Notice, Select } from "@/components/ui/primitives";
import { useApi } from "@/hooks/useApi";
import { api, explainError } from "@/lib/api/client";
import type { Me, TeamInfo, UserInfo } from "@/types/api";

/** Teams group people for reporting (the `team` field of security events). They do not grant or restrict access. */
export default function TeamsPage() {
  const me = useApi<Me>("auth/me");
  const role = me.data?.role as RoleName | undefined;
  const allowed = !!role && !!me.data?.user_id && roleHas(role, "users:manage");
  const teams = useApi<{ teams: TeamInfo[] }>(allowed ? "teams" : null);
  const users = useApi<{ users: UserInfo[] }>(allowed ? "users" : null);
  const [name, setName] = useState(""); const [error, setError] = useState<string | null>(null);
  const [pick, setPick] = useState<Record<string, string>>({});
  const emailOf = (id: string) => users.data?.users.find((u) => u.id === id)?.email ?? id.slice(0, 8);

  const act = async (fn: () => Promise<unknown>) => {
    setError(null);
    try { await fn(); teams.reload(); users.reload(); } catch (err) { setError(explainError(err)); }
  };

  return (
    <Shell title="Teams">
      {me.data && !allowed && <Notice kind="info">Managing teams requires the users:manage permission and a user session.</Notice>}
      {error && <Notice>{error}</Notice>}
      {allowed && (
        <>
          <Card title="Create a team">
            <form className="flex flex-wrap items-end gap-3" noValidate
              onSubmit={(e) => { e.preventDefault(); void act(async () => { await api.post("teams", { name: name.trim() }); setName(""); }); }}>
              <Field id="team-name" label="Name" value={name} onChange={(e) => setName(e.target.value)} maxLength={100} />
              <Button type="submit" disabled={name.trim() === ""}>Create</Button>
            </form>
            <p className="mt-2 text-xs text-slate-500">Teams are for grouping and reporting. Access is controlled by each person&apos;s role.</p>
          </Card>
          {teams.loading && !teams.data && <Loading />}
          {teams.data?.teams.length === 0 && <Card><p className="text-sm text-slate-500">No teams yet.</p></Card>}
          {teams.data?.teams.map((t) => {
            const candidates = users.data?.users.filter((u) => !u.disabled && !t.members.includes(u.id)) ?? [];
            return (
              <Card key={t.id} title={t.name}
                action={<Button variant="danger" onClick={() => { if (window.confirm(`Delete team "${t.name}"?`)) void act(() => api.del(`teams/${t.id}`)); }} aria-label={`Delete team ${t.name}`}>Delete</Button>}>
                <div className="flex flex-wrap gap-2">
                  {t.members.length === 0 && <span className="text-sm text-slate-500">No members.</span>}
                  {t.members.map((m) => (
                    <span key={m} className="inline-flex items-center gap-1">
                      <Chip>{emailOf(m)}</Chip>
                      <button type="button" className="text-xs text-rose-600 underline" aria-label={`Remove ${emailOf(m)} from ${t.name}`}
                        onClick={() => act(() => api.del(`teams/${t.id}/members/${m}`))}>remove</button>
                    </span>
                  ))}
                </div>
                {candidates.length > 0 && (
                  <div className="mt-3 flex flex-wrap items-end gap-2">
                    <Select id={`add-${t.id}`} label="Add member" value={pick[t.id] ?? ""} onChange={(e) => setPick({ ...pick, [t.id]: e.target.value })}>
                      <option value="">Choose...</option>
                      {candidates.map((u) => <option key={u.id} value={u.id}>{u.email}</option>)}
                    </Select>
                    <Button variant="secondary" disabled={!pick[t.id]} onClick={() => act(async () => { await api.put(`teams/${t.id}/members/${pick[t.id]}`, {}); setPick({ ...pick, [t.id]: "" }); })}>Add</Button>
                  </div>
                )}
              </Card>
            );
          })}
        </>
      )}
    </Shell>
  );
}
