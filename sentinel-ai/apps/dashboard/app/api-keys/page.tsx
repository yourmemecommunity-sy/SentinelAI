"use client";
import { ROLES, roleCanGrant, roleHas, type RoleName } from "@sentinelai/shared-types";
import { useState } from "react";
import { Shell } from "@/components/dashboard/Shell";
import { Button, Card, Chip, Field, Loading, Notice, Select } from "@/components/ui/primitives";
import { useApi } from "@/hooks/useApi";
import { api, describeError } from "@/lib/api/client";
import { formatTime } from "@/lib/utils/format";
import type { ApiKeyInfo, Me } from "@/types/api";

function status(k: ApiKeyInfo): { label: string; tone: string } {
  if (k.revoked_at) return { label: "Revoked", tone: "text-slate-500" };
  if (k.expires_at && new Date(k.expires_at) <= new Date()) return { label: "Expired", tone: "text-slate-500" };
  return { label: "Active", tone: "text-emerald-600" };
}

export default function ApiKeysPage() {
  const me = useApi<Me>("auth/me");
  const role = me.data?.role as RoleName | undefined;
  const isUser = !!me.data?.user_id;
  const allowed = !!role && isUser && roleHas(role, "keys:manage");
  const list = useApi<{ api_keys: ApiKeyInfo[] }>(allowed ? "api-keys" : null);

  const [name, setName] = useState(""); const [newRole, setNewRole] = useState<RoleName>("DEVELOPER"); const [days, setDays] = useState("90");
  const [busy, setBusy] = useState(false); const [error, setError] = useState<string | null>(null);
  // The plaintext key lives only in this component's memory: never in storage, never in the URL, cleared on dismiss.
  const [created, setCreated] = useState<{ key: string; name: string } | null>(null);
  const [copied, setCopied] = useState(false);

  const grantable = role ? ROLES.filter((r) => roleCanGrant(role, r)) : [];

  const create = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true); setError(null); setCopied(false);
    try {
      const k = await api.post<ApiKeyInfo & { key: string }>("api-keys", { name: name.trim(), role: newRole, expires_in_days: Number(days) });
      setCreated({ key: k.key, name: k.name }); setName(""); list.reload();
    } catch (err) { setError(describeError(err)); } finally { setBusy(false); }
  };

  const revoke = async (k: ApiKeyInfo) => {
    if (!window.confirm(`Revoke "${k.name}" (${k.prefix}...)? Applications using it will stop working immediately.`)) return;
    try { await api.del(`api-keys/${k.id}`); list.reload(); } catch (err) { setError(describeError(err)); }
  };

  const copy = async () => { try { await navigator.clipboard.writeText(created!.key); setCopied(true); } catch { setError("Could not copy automatically. Select and copy the key manually."); } };

  return (
    <Shell title="API keys">
      {me.loading && !me.data && <Loading />}
      {me.error && <Notice>{me.error}</Notice>}
      {me.data && !isUser && <Notice kind="info">API keys cannot manage API keys. Sign in as a user to continue.</Notice>}
      {me.data && isUser && !allowed && <Notice kind="info">Your role ({me.data.role}) cannot manage API keys.</Notice>}

      {created && (
        <Card title={`New key: ${created.name}`}>
          <Notice kind="success">
            Copy this key now. <strong>It will not be shown again</strong>; only a hash is stored.
          </Notice>
          <code data-testid="new-key" className="mt-3 block break-all rounded bg-slate-100 p-2 text-xs dark:bg-slate-800">{created.key}</code>
          <div className="mt-3 flex gap-2">
            <Button onClick={copy}>{copied ? "Copied" : "Copy key"}</Button>
            <Button variant="secondary" onClick={() => { setCreated(null); setCopied(false); }}>I have saved it</Button>
          </div>
        </Card>
      )}

      {allowed && (
        <>
          <Card title="Create a key">
            <form onSubmit={create} className="grid gap-3 md:grid-cols-4" noValidate>
              <Field id="key-name" label="Name" value={name} onChange={(e) => setName(e.target.value)} maxLength={100} placeholder="ci-pipeline" required />
              <Select id="key-role" label="Role" value={newRole} onChange={(e) => setNewRole(e.target.value as RoleName)}>
                {grantable.map((r) => <option key={r} value={r}>{r}</option>)}
              </Select>
              <Field id="key-days" label="Expires in (days)" type="number" min={1} max={365} value={days} onChange={(e) => setDays(e.target.value)} />
              <div className="flex items-end"><Button type="submit" disabled={busy || name.trim() === "" || grantable.length === 0}>{busy ? "Creating..." : "Create key"}</Button></div>
            </form>
            <p className="mt-2 text-xs text-slate-500">You can only create keys with permissions you already hold. Keys expire (default 90 days, max 365) and cannot create other keys.</p>
            {error && <div className="mt-3"><Notice>{error}</Notice></div>}
          </Card>

          <Card title="Keys">
            {list.loading && !list.data && <Loading />}
            {list.error && <Notice>{list.error}</Notice>}
            {list.data && list.data.api_keys.length === 0 && <p className="text-sm text-slate-500">No keys yet.</p>}
            {list.data && list.data.api_keys.length > 0 && (
              <div className="overflow-x-auto">
                <table className="w-full min-w-[640px] text-left text-sm">
                  <caption className="sr-only">API keys</caption>
                  <thead className="text-xs uppercase text-slate-500"><tr>{["Name", "Key", "Role", "Status", "Expires", "Last used", ""].map((h) => <th key={h} scope="col" className="px-2 py-2 font-medium">{h}</th>)}</tr></thead>
                  <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                    {list.data.api_keys.map((k) => {
                      const st = status(k);
                      return (
                        <tr key={k.id}>
                          <td className="px-2 py-2">{k.name}</td>
                          <td className="px-2 py-2"><Chip>{k.prefix}...</Chip></td>
                          <td className="px-2 py-2 text-xs">{k.role}</td>
                          <td className={`px-2 py-2 text-xs font-medium ${st.tone}`}>{st.label}</td>
                          <td className="px-2 py-2 text-xs text-slate-500">{k.expires_at ? formatTime(k.expires_at) : "never"}</td>
                          <td className="px-2 py-2 text-xs text-slate-500">{k.last_used_at ? formatTime(k.last_used_at) : "never"}</td>
                          <td className="px-2 py-2 text-right">
                            {st.label === "Active" && role && roleCanGrant(role, k.role) && <Button variant="danger" onClick={() => revoke(k)} aria-label={`Revoke ${k.name}`}>Revoke</Button>}
                          </td>
                        </tr>
                      );
                    })}
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
