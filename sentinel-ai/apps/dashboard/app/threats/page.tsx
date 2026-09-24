"use client";
import { Shell } from "@/components/dashboard/Shell";
import { EventsTable } from "@/components/security-events/EventsTable";
import { Card, Chip, Loading, Notice } from "@/components/ui/primitives";
import { useApi } from "@/hooks/useApi";
import { entityBreakdown, isThreat } from "@/lib/utils/stats";
import type { EventsPage } from "@/types/api";

export default function ThreatsPage() {
  const { data, error, loading } = useApi<EventsPage>("events?limit=200");
  const threats = data?.events.filter(isThreat) ?? [];
  const breakdown = entityBreakdown(threats).slice(0, 12);
  return (
    <Shell title="Threats">
      {error && <Notice>{error}</Notice>}
      {loading && !data && <Loading />}
      {data && (
        <>
          <p className="text-xs text-slate-500">HIGH/CRITICAL events, fail-closed events, and anything involving secrets or prompt-injection signals, from the {data.events.length} most recent events.</p>
          <Card title="Most frequent entities in these events">
            {breakdown.length === 0 ? <p className="text-sm text-slate-500">No threats in the recent window.</p> :
              <ul className="flex flex-wrap gap-2">{breakdown.map((b) => <li key={b.entity}><Chip>{b.entity}</Chip> <span className="text-xs tabular-nums text-slate-500">{b.count}</span></li>)}</ul>}
          </Card>
          <Card title={`${threats.length} threat event${threats.length === 1 ? "" : "s"}`}><EventsTable events={threats} empty="No threat events in the recent window." /></Card>
        </>
      )}
    </Shell>
  );
}
