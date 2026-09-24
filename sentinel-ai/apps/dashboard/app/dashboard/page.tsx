"use client";
import { StackedBars } from "@/components/charts/StackedBars";
import { ScanPlayground } from "@/components/dashboard/ScanPlayground";
import { Shell } from "@/components/dashboard/Shell";
import { EventsTable } from "@/components/security-events/EventsTable";
import { Card, Loading, Notice } from "@/components/ui/primitives";
import { useApi } from "@/hooks/useApi";
import { computeStats } from "@/lib/utils/stats";
import type { EventsPage, UsageRow } from "@/types/api";

function Stat({ label, value, tone }: { label: string; value: number; tone?: "danger" | "warn" }) {
  return (
    <div className="rounded-lg border border-slate-200 bg-white p-3 dark:border-slate-800 dark:bg-slate-900">
      <p className="text-xs text-slate-500">{label}</p>
      <p className={`text-2xl font-semibold tabular-nums ${tone === "danger" ? "text-red-600" : tone === "warn" ? "text-orange-600" : ""}`}>{value.toLocaleString()}</p>
    </div>
  );
}

const WINDOW = 200;

export default function OverviewPage() {
  const events = useApi<EventsPage>(`events?limit=${WINDOW}`);
  const usage = useApi<{ days: number; usage: UsageRow[] }>("usage?days=14");
  const loading = events.loading || usage.loading;
  const stats = events.data ? computeStats(events.data.events, usage.data?.usage ?? []) : null;
  const reload = () => { events.reload(); usage.reload(); };

  return (
    <Shell title="Overview">
      {(events.error || usage.error) && <Notice>{events.error ?? usage.error}</Notice>}
      {loading && !stats && <Loading />}
      {stats && (
        <>
          <p className="text-xs text-slate-500">Counts reflect the {events.data!.events.length} most recent events{events.data!.events.length === WINDOW ? " (window is capped)" : ""}. Usage chart covers the last 14 days.</p>
          <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
            <Stat label="Total requests" value={stats.totalRequests} />
            <Stat label="Blocked" value={stats.blocked} tone="danger" />
            <Stat label="Masked / sanitized" value={stats.masked} />
            <Stat label="Fail-closed events" value={stats.failedClosed} tone="warn" />
            <Stat label="Critical threats" value={stats.critical} tone="danger" />
            <Stat label="High threats" value={stats.high} tone="warn" />
            <Stat label="PII events" value={stats.pii} />
            <Stat label="Secret events" value={stats.secrets} />
            <Stat label="Prompt-injection events" value={stats.promptInjection} tone="danger" />
          </div>
          <div className="grid gap-4 lg:grid-cols-3">
            <Card title="Requests per day" className="lg:col-span-2"><StackedBars rows={usage.data?.usage ?? []} /></Card>
            <Card title="Provider usage">
              {stats.providers.length === 0 ? <p className="text-sm text-slate-500">No provider traffic yet.</p> : (
                <ul className="space-y-1 text-sm">{stats.providers.map((p) => <li key={p.provider} className="flex justify-between"><span>{p.provider}</span><span className="tabular-nums">{p.requests.toLocaleString()}</span></li>)}</ul>
              )}
            </Card>
          </div>
        </>
      )}
      <ScanPlayground onScanned={reload} />
      {events.data && <Card title="Latest events"><EventsTable events={events.data.events.slice(0, 8)} empty="No events yet. Send a request through the gateway or try the playground." /></Card>}
    </Shell>
  );
}
