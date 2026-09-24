import type { UsageRow } from "@/types/api";

interface Day { day: string; allowed: number; sanitized: number; blocked: number }

/** Aggregate usage rows (per day/provider) into per-day allowed / sanitized / blocked counts, oldest first. */
export function byDay(rows: UsageRow[]): Day[] {
  const m = new Map<string, Day>();
  for (const r of rows) {
    const d = m.get(r.day) ?? { day: r.day, allowed: 0, sanitized: 0, blocked: 0 };
    d.blocked += r.blocked; d.sanitized += r.sanitized; d.allowed += Math.max(0, r.requests - r.blocked - r.sanitized);
    m.set(r.day, d);
  }
  return [...m.values()].sort((a, b) => a.day.localeCompare(b.day));
}

const SERIES = [
  { key: "blocked", label: "Blocked", fill: "#dc2626" },
  { key: "sanitized", label: "Sanitized", fill: "#0284c7" },
  { key: "allowed", label: "Allowed", fill: "#64748b" },
] as const;

/** Accessible stacked bar chart (SVG). A data table alternative is rendered for screen readers. */
export function StackedBars({ rows, height = 180 }: { rows: UsageRow[]; height?: number }) {
  const days = byDay(rows);
  if (days.length === 0) return <p className="text-sm text-slate-500">No usage recorded in this period.</p>;
  const max = Math.max(1, ...days.map((d) => d.allowed + d.sanitized + d.blocked));
  const w = 640; const pad = 24; const bw = Math.max(6, Math.min(40, (w - pad * 2) / days.length - 6));
  const step = (w - pad * 2) / days.length;
  return (
    <div>
      <svg role="img" aria-label={`Requests per day, ${days.length} days, peak ${max}`} viewBox={`0 0 ${w} ${height + 20}`} className="w-full">
        {days.map((d, i) => {
          let y = height;
          const x = pad + i * step + (step - bw) / 2;
          return (
            <g key={d.day}>
              {SERIES.map((s) => {
                const h = (d[s.key] / max) * (height - 8);
                y -= h;
                return h > 0 ? <rect key={s.key} x={x} y={y} width={bw} height={h} fill={s.fill}><title>{`${d.day} ${s.label}: ${d[s.key]}`}</title></rect> : null;
              })}
              {(days.length <= 10 || i % Math.ceil(days.length / 10) === 0) && (
                <text x={x + bw / 2} y={height + 14} textAnchor="middle" fontSize="9" fill="currentColor" opacity="0.6">{d.day.slice(5)}</text>
              )}
            </g>
          );
        })}
        <line x1={pad} x2={w - pad} y1={height} y2={height} stroke="currentColor" opacity="0.2" />
      </svg>
      <ul className="mt-2 flex flex-wrap gap-4 text-xs">
        {SERIES.map((s) => <li key={s.key} className="flex items-center gap-1"><span aria-hidden className="inline-block h-2.5 w-2.5 rounded-sm" style={{ background: s.fill }} />{s.label}</li>)}
      </ul>
      <table className="sr-only"><caption>Requests per day</caption><thead><tr><th>Day</th><th>Allowed</th><th>Sanitized</th><th>Blocked</th></tr></thead>
        <tbody>{days.map((d) => <tr key={d.day}><td>{d.day}</td><td>{d.allowed}</td><td>{d.sanitized}</td><td>{d.blocked}</td></tr>)}</tbody></table>
    </div>
  );
}
