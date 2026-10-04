"use client";
import { AsrTrend } from "@/components/charts/AsrTrend";
import { Shell } from "@/components/dashboard/Shell";
import { Card, Chip, Loading, Notice } from "@/components/ui/primitives";
import { useApi } from "@/hooks/useApi";
import { formatTime } from "@/lib/utils/format";
import type { RedTeamRound } from "@/types/api";

const pct = (n: number, d: number) => (d ? `${((100 * n) / d).toFixed(1)}%` : "-");

export default function RedTeamPage() {
  const { data, error, loading } = useApi<{ rounds: RedTeamRound[] }>("red-team/rounds");
  const rounds = data?.rounds ?? [];
  const latest = rounds[0];
  const categories = [...new Set(rounds.flatMap((r) => Object.keys(r.per_category)))].sort();
  return (
    <Shell title="Red team">
      <Notice kind="info">
        An attacker model writes new prompt attacks against this Sentinel instance; every round is scored and the attacks that got through are
        kept as a regression set. Attacks are synthetic. A generator&apos;s own blind spots limit what it finds: a low success rate means
        &quot;hard for this generator&quot;, not &quot;safe&quot;.
      </Notice>
      {loading && <Loading />}
      {error && <Notice>{error}</Notice>}
      {!loading && !error && rounds.length === 0 && <Notice kind="info">No rounds yet. Run <code>python scripts/security/red_team.py --post</code>.</Notice>}
      {latest && (
        <>
          <Card title={`Latest: round ${latest.round}`}>
            <p className="text-sm">
              {latest.attacks} attacks by <Chip>{latest.generator_model}</Chip>: <b className="text-red-600">{latest.slipped} slipped through</b> ({pct(latest.slipped, latest.attacks)}),
              {" "}{latest.blocked} blocked. {latest.ran_at ? formatTime(latest.ran_at) : ""} · cost ${latest.cost_usd.toFixed(4)}
            </p>
          </Card>
          <Card title="Attack success rate over rounds"><AsrTrend rounds={rounds} /></Card>
          <Card title="Attack success rate per category">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead><tr className="text-left text-slate-500"><th className="py-1 pr-3">Round</th>{categories.map((c) => <th key={c} className="py-1 pr-3">{c.replaceAll("_", " ")}</th>)}<th>Total</th></tr></thead>
                <tbody>
                  {rounds.map((r) => (
                    <tr key={r.round} className="border-t border-slate-100 dark:border-slate-800">
                      <td className="py-1 pr-3">R{r.round}</td>
                      {categories.map((c) => { const v = r.per_category[c]; return <td key={c} className="py-1 pr-3">{v ? `${pct(v.slipped, v.attacks)} (${v.slipped}/${v.attacks})` : "-"}</td>; })}
                      <td className="py-1 font-medium">{pct(r.slipped, r.attacks)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
          <Card title={`Blocked by tier, round ${latest.round}`}>
            <ul className="text-sm">
              {Object.entries(Object.values(latest.per_category).reduce<Record<string, number>>((acc, c) => {
                for (const [k, v] of Object.entries(c.by_tier ?? {})) acc[k] = (acc[k] ?? 0) + v; return acc;
              }, {})).map(([tier, n]) => <li key={tier}>{tier}: {n}</li>)}
            </ul>
          </Card>
          <Card title={`Examples, round ${latest.round} (sanitized, truncated)`}>
            <ul className="space-y-2 text-sm">
              {latest.examples.map((ex, i) => (
                <li key={i} className="border-l-2 pl-2" style={{ borderColor: ex.outcome === "slipped" ? "#dc2626" : "#16a34a" }}>
                  <span className="text-xs text-slate-500">{ex.category.replaceAll("_", " ")} · {ex.outcome}{ex.outcome === "blocked" ? ` by ${ex.decided_by}` : ""}</span>
                  <p className="break-words font-mono text-xs">{ex.text}</p>
                </li>
              ))}
            </ul>
          </Card>
        </>
      )}
    </Shell>
  );
}
