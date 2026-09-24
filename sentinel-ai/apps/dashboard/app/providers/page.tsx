"use client";
import { roleHas, type RoleName } from "@sentinelai/shared-types";
import { useState } from "react";
import { Shell } from "@/components/dashboard/Shell";
import { Button, Card, Field, Loading, Notice } from "@/components/ui/primitives";
import { useApi } from "@/hooks/useApi";
import { api, explainError } from "@/lib/api/client";
import { formatTime } from "@/lib/utils/format";
import type { Me, ProviderSetting } from "@/types/api";

const SOURCE: Record<ProviderSetting["source"], string> = {
  organization: "Your organization's key",
  platform: "Platform key (operator)",
  disabled: "Disabled for your organization",
  none: "Not available",
};

export default function ProvidersPage() {
  const me = useApi<Me>("auth/me");
  const role = me.data?.role as RoleName | undefined;
  const allowed = !!role && !!me.data?.user_id && roleHas(role, "providers:manage");
  const list = useApi<{ credential_storage: string; providers: ProviderSetting[] }>(allowed ? "providers" : null);
  const [editing, setEditing] = useState<string | null>(null);
  // The key is held only while the form is open and is cleared on submit or cancel; it is never displayed again.
  const [key, setKey] = useState(""); const [error, setError] = useState<string | null>(null); const [busy, setBusy] = useState(false);

  const act = async (fn: () => Promise<unknown>) => {
    setError(null); setBusy(true);
    try { await fn(); list.reload(); } catch (err) { setError(explainError(err)); } finally { setBusy(false); }
  };
  const save = (provider: string) => act(async () => { try { await api.put(`providers/${provider}/credential`, { api_key: key.trim() }); setEditing(null); } finally { setKey(""); } });

  return (
    <Shell title="AI providers">
      {me.data && !allowed && <Notice kind="info">Managing providers requires the providers:manage permission and a user session.</Notice>}
      {error && <Notice>{error}</Notice>}
      {allowed && list.loading && !list.data && <Loading />}
      {list.data?.credential_storage === "not_configured" && (
        <Notice kind="info">Credential storage is not configured on this deployment. Your organization uses the operator&apos;s provider keys.</Notice>
      )}
      {list.data?.providers.map((p) => (
        <Card key={p.provider} title={p.provider}
          action={<Button variant="secondary" disabled={busy} onClick={() => act(() => api.patch(`providers/${p.provider}`, { enabled: !p.enabled }))}>{p.enabled ? "Disable" : "Enable"}</Button>}>
          <p className="text-sm"><span className="text-slate-500">Requests use:</span> <strong>{SOURCE[p.source]}</strong></p>
          {p.organization_credential && (
            <p className="mt-1 text-xs text-slate-500">Stored key ending in <code>{p.organization_credential.hint ?? "????"}</code>, updated {formatTime(p.organization_credential.updated_at)}. Encrypted at rest; it cannot be viewed.</p>
          )}
          {p.accepts_organization_credential && list.data?.credential_storage === "available" && (
            editing === p.provider ? (
              <form className="mt-3 flex flex-wrap items-end gap-2" noValidate onSubmit={(e) => { e.preventDefault(); void save(p.provider); }}>
                <Field id={`key-${p.provider}`} label="API key" type="password" autoComplete="off" value={key} onChange={(e) => setKey(e.target.value)} maxLength={512} />
                <Button type="submit" disabled={busy || key.trim().length < 16}>Save</Button>
                <Button variant="secondary" type="button" onClick={() => { setEditing(null); setKey(""); }}>Cancel</Button>
              </form>
            ) : (
              <div className="mt-3 flex gap-2">
                <Button variant="secondary" onClick={() => { setEditing(p.provider); setKey(""); }}>{p.organization_credential ? "Replace key" : "Use our own key"}</Button>
                {p.organization_credential && (
                  <Button variant="danger" disabled={busy} onClick={() => { if (window.confirm(`Remove your ${p.provider} key? Requests fall back to the platform key if one is configured.`)) void act(() => api.del(`providers/${p.provider}/credential`)); }}>Remove key</Button>
                )}
              </div>
            )
          )}
        </Card>
      ))}
    </Shell>
  );
}
