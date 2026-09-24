"use client";
import { useState } from "react";
import { StackedBars } from "@/components/charts/StackedBars";
import { Shell } from "@/components/dashboard/Shell";
import { Card, Loading, Notice, Select } from "@/components/ui/primitives";
import { useApi } from "@/hooks/useApi";
import type { UsageRow } from "@/types/api";

export default function UsagePage() {
  const [days, setDays] = useState("30");
  const { data, error, loading } = useApi<{ days: number; usage: UsageRow[] }>(`usage?days=${days}`);
  const rows = data?.usage ?? [];
  const totals = rows.reduce((t, r) => ({ requests: t.requests + r.requests, blocked: t.blocked + r.blocked, sanitized: t.sanitized + r.sanitized }), { requests: 0, blocked: 0, sanitized: 0 });
  return (
    <Shell title="Usage">
      <div className="max-w-[10rem]"><Select id="days" label="Period" value={days} onChange={(e) => setDays(e.target.value)}>{["7", "14", "30", "90"].map((d) => <option key={d} value={d}>Last {d} days</option>)}</Select></div>
      {error && <Notice>{error}</Notice>}
      {loading && !data && <Loading />}
      {data && (
        <>
          <Card title="Requests per day"><StackedBars rows={rows} /></Card>
          <Card title={`By day and provider (${totals.requests.toLocaleString()} requests, ${totals.blocked.toLocaleString()} blocked, ${totals.sanitized.toLocaleString()} sanitized)`}>
            {rows.length === 0 ? <p className="text-sm text-slate-500">No usage in this period.</p> : (
              <div className="overflow-x-auto"><table className="w-full text-left text-sm">
                <caption className="sr-only">Usage by day and provider</caption>
                <thead className="text-xs uppercase text-slate-500"><tr>{["Day", "Provider", "Requests", "Blocked", "Sanitized"].map((h) => <th key={h} scope="col" className="px-2 py-2 font-medium">{h}</th>)}</tr></thead>
                <tbody className="divide-y divide-slate-100 dark:divide-slate-800">{rows.map((r) => (
                  <tr key={`${r.day}-${r.provider}`}><td className="px-2 py-1.5">{r.day}</td><td className="px-2 py-1.5">{r.provider}</td>
                    <td className="px-2 py-1.5 tabular-nums">{r.requests}</td><td className="px-2 py-1.5 tabular-nums">{r.blocked}</td><td className="px-2 py-1.5 tabular-nums">{r.sanitized}</td></tr>))}</tbody>
              </table></div>
            )}
          </Card>
        </>
      )}
    </Shell>
  );
}
