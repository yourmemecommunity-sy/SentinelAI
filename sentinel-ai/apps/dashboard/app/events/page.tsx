"use client";
import { ACTIONS, SEVERITIES } from "@sentinelai/shared-types";
import { useCallback, useEffect, useState } from "react";
import { Shell } from "@/components/dashboard/Shell";
import { EventsTable } from "@/components/security-events/EventsTable";
import { Button, Card, Loading, Notice, Select } from "@/components/ui/primitives";
import { api, describeError } from "@/lib/api/client";
import type { EventsPage, SecurityEvent } from "@/types/api";

const TYPES = ["scan", "ai_request", "ai_response", "fail_closed", "file_scan"] as const;
const PAGE = 50;

export default function EventsPage() {
  const [risk, setRisk] = useState(""); const [action, setAction] = useState(""); const [type, setType] = useState(""); const [q, setQ] = useState("");
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [next, setNext] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const query = useCallback((before?: string) => {
    const p = new URLSearchParams({ limit: String(PAGE) });
    if (risk) p.set("risk_level", risk); if (action) p.set("action", action); if (type) p.set("event_type", type); if (before) p.set("before", before);
    return `events?${p}`;
  }, [risk, action, type]);

  useEffect(() => {
    let cancelled = false;
    setLoading(true); setError(null);
    api.get<EventsPage>(query())
      .then((d) => { if (!cancelled) { setEvents(d.events); setNext(d.next_before); } })
      .catch((e) => { if (!cancelled) setError(describeError(e)); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [query]);

  const more = async () => {
    if (!next) return;
    setLoading(true);
    try { const d = await api.get<EventsPage>(query(next)); setEvents((prev) => [...prev, ...d.events]); setNext(d.next_before); }
    catch (e) { setError(describeError(e)); } finally { setLoading(false); }
  };

  // Free-text search runs client-side over the loaded page(s): it matches ids, entity types, providers, models and policies.
  const needle = q.trim().toLowerCase();
  const shown = needle ? events.filter((e) => [e.id, e.request_id, e.provider, e.model, e.policy_id, e.application, ...e.entity_types].some((v) => v?.toLowerCase().includes(needle))) : events;

  const exportCsv = () => {
    const cols = ["timestamp", "id", "event_type", "direction", "risk_level", "risk_score", "action", "entity_types", "provider", "model", "policy_id", "failed_closed"] as const;
    const esc = (v: unknown) => `"${String(Array.isArray(v) ? v.join("|") : v ?? "").replace(/"/g, '""')}"`;
    // Guard against spreadsheet formula injection from any string field.
    const safe = (v: unknown) => { const s = esc(v); return /^"[=+\-@\t\r]/.test(s) ? `"'${s.slice(1)}` : s; };
    const csv = [cols.join(","), ...shown.map((e) => cols.map((c) => safe(e[c])).join(","))].join("\n");
    const url = URL.createObjectURL(new Blob([csv], { type: "text/csv" }));
    const a = Object.assign(document.createElement("a"), { href: url, download: "security-events.csv" });
    a.click(); URL.revokeObjectURL(url);
  };

  return (
    <Shell title="Security events">
      <Card>
        <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
          <Select id="f-risk" label="Risk level" value={risk} onChange={(e) => setRisk(e.target.value)}><option value="">All</option>{SEVERITIES.map((s) => <option key={s}>{s}</option>)}</Select>
          <Select id="f-action" label="Action" value={action} onChange={(e) => setAction(e.target.value)}><option value="">All</option>{ACTIONS.map((a) => <option key={a}>{a}</option>)}</Select>
          <Select id="f-type" label="Event type" value={type} onChange={(e) => setType(e.target.value)}><option value="">All</option>{TYPES.map((t) => <option key={t}>{t}</option>)}</Select>
          <div className="col-span-2">
            <label htmlFor="f-q" className="mb-1 block text-xs font-medium text-slate-600 dark:text-slate-300">Search loaded events</label>
            <input id="f-q" value={q} onChange={(e) => setQ(e.target.value)} placeholder="id, entity, provider, policy..." maxLength={100}
              className="w-full rounded-md border border-slate-300 bg-white px-3 py-1.5 text-sm dark:border-slate-700 dark:bg-slate-800" />
          </div>
        </div>
      </Card>
      {error && <Notice>{error}</Notice>}
      <Card title={`${shown.length} event${shown.length === 1 ? "" : "s"}`} action={<Button variant="secondary" onClick={exportCsv} disabled={shown.length === 0}>Export CSV</Button>}>
        {loading && events.length === 0 ? <Loading /> : <EventsTable events={shown} />}
        {next && <div className="mt-3 text-center"><Button variant="secondary" onClick={more} disabled={loading}>{loading ? "Loading..." : "Load more"}</Button></div>}
      </Card>
    </Shell>
  );
}
