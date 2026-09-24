import Link from "next/link";
import { ActionBadge, Chip, RiskBadge } from "@/components/ui/primitives";
import { formatTime, shortId } from "@/lib/utils/format";
import type { SecurityEvent } from "@/types/api";

export function EventsTable({ events, empty = "No events match these filters." }: { events: SecurityEvent[]; empty?: string }) {
  if (events.length === 0) return <p className="py-6 text-center text-sm text-slate-500">{empty}</p>;
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[720px] text-left text-sm">
        <caption className="sr-only">Security events, newest first</caption>
        <thead className="text-xs uppercase text-slate-500">
          <tr>{["Time", "Event", "Risk", "Action", "Entities", "Provider", "Policy"].map((h) => <th key={h} scope="col" className="px-2 py-2 font-medium">{h}</th>)}</tr>
        </thead>
        <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
          {events.map((e) => (
            <tr key={e.id} className="hover:bg-slate-50 dark:hover:bg-slate-800/50">
              <td className="whitespace-nowrap px-2 py-2 text-xs text-slate-500">{formatTime(e.timestamp)}</td>
              <td className="px-2 py-2">
                <Link href={`/events/${e.id}`} className="font-mono text-xs text-indigo-600 hover:underline dark:text-indigo-400">{shortId(e.id)}</Link>
                <div className="text-[11px] text-slate-500">{e.event_type} · {e.direction}{e.failed_closed && <span className="ml-1 font-medium text-red-600">fail-closed</span>}</div>
              </td>
              <td className="px-2 py-2"><RiskBadge level={e.risk_level} /> <span className="text-xs text-slate-500">{e.risk_score}</span></td>
              <td className="px-2 py-2"><ActionBadge action={e.action} /></td>
              <td className="px-2 py-2"><div className="flex flex-wrap gap-1">{e.entity_types.length ? e.entity_types.map((t) => <Chip key={t}>{t}</Chip>) : <span className="text-xs text-slate-400">none</span>}</div></td>
              <td className="px-2 py-2 text-xs">{e.provider ?? "-"}{e.model ? <span className="text-slate-500"> / {e.model}</span> : null}</td>
              <td className="px-2 py-2 text-xs text-slate-500">{e.policy_id}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
