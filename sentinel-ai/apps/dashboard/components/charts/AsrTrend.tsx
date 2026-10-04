import type { RedTeamRound } from "@/types/api";

const pct = (n: number, d: number) => (d ? `${((100 * n) / d).toFixed(1)}%` : "-");

/** Attack success rate per round (oldest first) as an accessible SVG line, with the numbers in a table for screen readers. */
export function AsrTrend({ rounds }: { rounds: RedTeamRound[] }) {
  const pts = [...rounds].sort((a, b) => a.round - b.round);
  if (pts.length === 0) return null;
  const w = 600; const h = 140; const pad = 28;
  const x = (i: number) => pad + (pts.length === 1 ? (w - 2 * pad) / 2 : (i * (w - 2 * pad)) / (pts.length - 1));
  const y = (r: RedTeamRound) => h - pad - ((r.attacks ? r.slipped / r.attacks : 0) * (h - 2 * pad));
  return (
    <figure>
      <svg viewBox={`0 0 ${w} ${h}`} role="img" aria-label="Attack success rate per round" className="w-full max-w-2xl">
        <line x1={pad} y1={h - pad} x2={w - pad} y2={h - pad} stroke="#94a3b8" />
        <line x1={pad} y1={pad} x2={pad} y2={h - pad} stroke="#94a3b8" />
        <text x={4} y={pad + 4} fontSize="10" fill="#64748b">100%</text>
        <text x={8} y={h - pad} fontSize="10" fill="#64748b">0%</text>
        <polyline fill="none" stroke="#dc2626" strokeWidth={2} points={pts.map((r, i) => `${x(i)},${y(r)}`).join(" ")} />
        {pts.map((r, i) => (
          <g key={r.round}>
            <circle cx={x(i)} cy={y(r)} r={3.5} fill="#dc2626" />
            <text x={x(i)} y={h - 10} fontSize="10" textAnchor="middle" fill="#64748b">R{r.round}</text>
          </g>
        ))}
      </svg>
      <figcaption className="sr-only">
        {pts.map((r) => `Round ${r.round}: ${pct(r.slipped, r.attacks)} of ${r.attacks} attacks slipped through`).join("; ")}
      </figcaption>
    </figure>
  );
}
