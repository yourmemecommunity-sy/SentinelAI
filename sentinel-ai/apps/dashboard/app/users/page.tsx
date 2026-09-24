"use client";
import { ROLES, roleCanGrant, roleHas, type RoleName } from "@sentinelai/shared-types";
import { useState } from "react";
import { Shell } from "@/components/dashboard/Shell";
import { Button, Card, Chip, Field, Loading, Notice, Select } from "@/components/ui/primitives";
import { useApi } from "@/hooks/useApi";
import { api, explainError } from "@/lib/api/client";
import { formatTime } from "@/lib/utils/format";
import type { InvitationInfo, Me, UserInfo } from "@/types/api";

export default function UsersPage() {
  const me = useApi<Me>("auth/me");
  const role = me.data?.role as RoleName | undefined;
  const isUser = !!me.data?.user_id;
  const allowed = !!role && isUser && roleHas(role, "users:manage");
  const users = useApi<{ users: UserInfo[] }>(allowed ? "users" : null);
  const invites = useApi<{ invitations: InvitationInfo[] }>(allowed ? "invitations" : null);
  const grantable = role ? ROLES.filter((r) => roleCanGrant(role, r)) : [];

  const [email, setEmail] = useState(""); const [inviteRole, setInviteRole] = useState<RoleName>("DEVELOPER"); const [hours, setHours] = useState("72");
  const [busy, setBusy] = useState(false); const [error, setError] = useState<string | null>(null);
  // The invitation link exists only in this component's memory; it is never stored and cannot be shown again.
  const [link, setLink] = useState<{ email: string; url: string } | null>(null);
  const [copied, setCopied] = useState(false);

  const act = async (fn: () => Promise<unknown>) => {
    setError(null);
    try { await fn(); users.reload(); invites.reload(); } catch (err) { setError(explainError(err)); }
  };

  const invite = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true); setError(null); setCopied(false);
    try {
      const r = await api.post<InvitationInfo & { token: string }>("invitations", { email: email.trim(), role: inviteRole, expires_in_hours: Number(hours) });
      setLink({ email: r.email, url: `${window.location.origin}/accept-invite#${r.token}` }); setEmail(""); invites.reload();
    } catch (err) { setError(explainError(err)); } finally { setBusy(false); }
  };

  const setUserRole = (u: UserInfo, r: RoleName) => {
    if (r === u.role) return;
    if (!window.confirm(`Change ${u.email} from ${u.role} to ${r}? It takes effect on their next request.`)) return;
    void act(() => api.patch(`users/${u.id}`, { role: r }));
  };
  const toggle = (u: UserInfo) => {
    if (!u.disabled && !window.confirm(`Disable ${u.email}? They are signed out everywhere immediately.`)) return;
    void act(() => api.patch(`users/${u.id}`, { disabled: !u.disabled }));
  };
  const copy = async () => { try { await navigator.clipboard.writeText(link!.url); setCopied(true); } catch { setError("Could not copy automatically. Select and copy the link manually."); } };

  return (
    <Shell title="Users">
      {me.loading && !me.data && <Loading />}
      {me.error && <Notice>{me.error}</Notice>}
      {me.data && !isUser && <Notice kind="info">API keys cannot manage users. Sign in as a user to continue.</Notice>}
      {me.data && isUser && !allowed && <Notice kind="info">Your role ({me.data.role}) cannot manage users.</Notice>}
      {error && <Notice>{error}</Notice>}

      {link && (
        <Card title={`Invitation for ${link.email}`}>
          <Notice kind="success">Send this link to the invitee over a trusted channel. <strong>It will not be shown again.</strong></Notice>
          <code data-testid="invite-link" className="mt-3 block break-all rounded bg-slate-100 p-2 text-xs dark:bg-slate-800">{link.url}</code>
          <div className="mt-3 flex gap-2">
            <Button onClick={copy}>{copied ? "Copied" : "Copy link"}</Button>
            <Button variant="secondary" onClick={() => { setLink(null); setCopied(false); }}>Done</Button>
          </div>
        </Card>
      )}

      {allowed && (
        <>
          <Card title="Invite someone">
            <form onSubmit={invite} className="grid gap-3 md:grid-cols-4" noValidate>
              <Field id="invite-email" label="Email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} maxLength={254} required />
              <Select id="invite-role" label="Role" value={inviteRole} onChange={(e) => setInviteRole(e.target.value as RoleName)}>
                {grantable.map((r) => <option key={r} value={r}>{r}</option>)}
              </Select>
              <Field id="invite-hours" label="Expires in (hours)" type="number" min={1} max={168} value={hours} onChange={(e) => setHours(e.target.value)} />
              <div className="flex items-end"><Button type="submit" disabled={busy || email.trim() === ""}>{busy ? "Inviting..." : "Create invitation"}</Button></div>
            </form>
            <p className="mt-2 text-xs text-slate-500">You can only grant roles whose permissions you already hold. Links are single-use and expire (max 7 days).</p>
          </Card>

          <Card title="Members">
            {users.loading && !users.data && <Loading />}
            {users.error && <Notice>{users.error}</Notice>}
            {users.data && (
              <div className="overflow-x-auto">
                <table className="w-full min-w-[640px] text-left text-sm">
                  <caption className="sr-only">Organization members</caption>
                  <thead className="text-xs uppercase text-slate-500"><tr>{["Email", "Role", "Status", "Teams", "Joined", ""].map((h) => <th key={h} scope="col" className="px-2 py-2 font-medium">{h}</th>)}</tr></thead>
                  <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                    {users.data.users.map((u) => {
                      const self = u.id === me.data?.user_id;
                      const editable = !self && !!role && roleCanGrant(role, u.role);
                      return (
                        <tr key={u.id}>
                          <td className="px-2 py-2">{u.email}{self && <span className="ml-1 text-xs text-slate-500">(you)</span>}</td>
                          <td className="px-2 py-2 text-xs">
                            {editable ? (
                              <select aria-label={`Role for ${u.email}`} className="rounded border border-slate-300 bg-transparent px-1 py-0.5 dark:border-slate-700"
                                value={u.role} onChange={(e) => setUserRole(u, e.target.value as RoleName)}>
                                {grantable.map((r) => <option key={r} value={r}>{r}</option>)}
                              </select>
                            ) : u.role}
                          </td>
                          <td className={`px-2 py-2 text-xs font-medium ${u.disabled ? "text-slate-500" : "text-emerald-600"}`}>{u.disabled ? "Disabled" : "Active"}</td>
                          <td className="px-2 py-2">{u.teams.map((t) => <Chip key={t}>{t}</Chip>)}</td>
                          <td className="px-2 py-2 text-xs text-slate-500">{formatTime(u.created_at)}</td>
                          <td className="px-2 py-2 text-right">
                            {editable && <Button variant={u.disabled ? "secondary" : "danger"} onClick={() => toggle(u)} aria-label={`${u.disabled ? "Enable" : "Disable"} ${u.email}`}>{u.disabled ? "Enable" : "Disable"}</Button>}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </Card>

          <Card title="Invitations">
            {invites.data && invites.data.invitations.length === 0 && <p className="text-sm text-slate-500">No invitations yet.</p>}
            {invites.data && invites.data.invitations.length > 0 && (
              <div className="overflow-x-auto">
                <table className="w-full min-w-[560px] text-left text-sm">
                  <caption className="sr-only">Invitations</caption>
                  <thead className="text-xs uppercase text-slate-500"><tr>{["Email", "Role", "Status", "Expires", ""].map((h) => <th key={h} scope="col" className="px-2 py-2 font-medium">{h}</th>)}</tr></thead>
                  <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                    {invites.data.invitations.map((i) => (
                      <tr key={i.id}>
                        <td className="px-2 py-2">{i.email}</td>
                        <td className="px-2 py-2 text-xs">{i.role}</td>
                        <td className="px-2 py-2 text-xs capitalize">{i.status}</td>
                        <td className="px-2 py-2 text-xs text-slate-500">{formatTime(i.expires_at)}</td>
                        <td className="px-2 py-2 text-right">
                          {i.status === "pending" && role && roleCanGrant(role, i.role) &&
                            <Button variant="danger" onClick={() => act(() => api.del(`invitations/${i.id}`))} aria-label={`Revoke invitation for ${i.email}`}>Revoke</Button>}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Card>
        </>
      )}
    </Shell>
  );
}
