"use client";
import { Shell } from "@/components/dashboard/Shell";
import { Card, Chip, Loading, Notice } from "@/components/ui/primitives";
import { useApi } from "@/hooks/useApi";
import type { Me } from "@/types/api";

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
      <Notice kind="info">
        Organization retention, provider credentials, users, teams, API keys and the audit-log viewer are managed through APIs that are not yet available;
        they will appear here when they are.
      </Notice>
    </Shell>
  );
}
