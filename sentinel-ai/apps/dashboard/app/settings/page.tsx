"use client";
import { useEffect, useState } from "react";
import { Shell } from "@/components/dashboard/Shell";
import { Button, Card, Chip, Loading, Notice } from "@/components/ui/primitives";
import { useApi } from "@/hooks/useApi";
import { api, ApiError } from "@/lib/api/client";
import type { Me } from "@/types/api";

/** Organization switch for the external AI judge (tier 3). Writers need policies:write; the gateway audit-logs every change. */
function JudgeSwitch() {
  const { data, error } = useApi<{ external_judge: boolean }>("organization/ai-judge");
  const [enabled, setEnabled] = useState<boolean | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  useEffect(() => { if (data) setEnabled(data.external_judge); }, [data]);
  const toggle = async () => {
    setMsg(null);
    try { setEnabled((await api.put<{ external_judge: boolean }>("organization/ai-judge", { external_judge: !enabled })).external_judge); }
    catch (err) { setMsg(err instanceof ApiError && err.status === 403 ? "Only roles with policies:write can change this." : "Could not save."); }
  };
  return (
    <Card title="External AI judge">
      {error && <Notice>{error}</Notice>}
      {enabled !== null && (
        <>
          <p className="mb-2 text-sm">
            When the local classifier is unsure, SentinelAI can ask an external AI model to decide. It only ever receives text that
            SentinelAI has already masked, and its verdicts are cached. Status: <b>{enabled ? "on" : "off"}</b>.
          </p>
          <Button variant={enabled ? "danger" : "primary"} onClick={toggle}>{enabled ? "Turn off for this organization" : "Turn on"}</Button>
          {msg && <Notice>{msg}</Notice>}
        </>
      )}
    </Card>
  );
}

export default function SettingsPage() {
  const { data, error, loading } = useApi<Me>("auth/me");
  return (
    <Shell title="Settings">
      {error && <Notice>{error}</Notice>}
      {loading && !data && <Loading />}
      {data && (
        <Card title="Your session">
          <dl className="space-y-2 text-sm">
            <div className="flex gap-3"><dt className="w-32 text-slate-500">Role</dt><dd><Chip>{data.role}</Chip></dd></div>
            <div className="flex gap-3"><dt className="w-32 text-slate-500">User id</dt><dd className="break-all">{data.user_id ?? "-"}</dd></div>
            <div className="flex gap-3"><dt className="w-32 text-slate-500">Organization id</dt><dd className="break-all">{data.organization_id}</dd></div>
          </dl>
        </Card>
      )}
      <JudgeSwitch />
      <Notice kind="info">
        Organization retention, provider credentials, users, teams, API keys and the audit-log viewer are managed through APIs that are not yet available;
        they will appear here when they are.
      </Notice>
    </Shell>
  );
}
