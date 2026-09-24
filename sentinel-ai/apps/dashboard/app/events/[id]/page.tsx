"use client";
import Link from "next/link";
import { use } from "react";
import { Shell } from "@/components/dashboard/Shell";
import { ActionBadge, Card, Chip, Loading, Notice, RiskBadge } from "@/components/ui/primitives";
import { useApi } from "@/hooks/useApi";
import { formatTime } from "@/lib/utils/format";
import type { SecurityEvent } from "@/types/api";

const Row = ({ k, children }: { k: string; children: React.ReactNode }) => (
  <div className="grid grid-cols-3 gap-2 border-b border-slate-100 py-2 text-sm last:border-0 dark:border-slate-800"><dt className="text-slate-500">{k}</dt><dd className="col-span-2 break-all">{children}</dd></div>
);

export default function EventDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const { data: e, error, loading } = useApi<SecurityEvent>(/^[0-9a-fA-F-]{36}$/.test(id) ? `events/${id}` : null);
  return (
    <Shell title="Event detail">
      <p><Link href="/events" className="text-sm text-indigo-600 hover:underline">&larr; All events</Link></p>
      {loading && <Loading />}
      {!loading && !e && <Notice>{error ?? "Event not found."}</Notice>}
      {e && (
        <>
          <Notice kind="info">SentinelAI never stores prompt or response content. Events hold metadata only: what was detected, where the decision came from, and the action taken.</Notice>
          <Card title={`Event ${e.id}`}>
            <dl>
              <Row k="Time">{formatTime(e.timestamp)}</Row>
              <Row k="Type">{e.event_type} ({e.direction})</Row>
              <Row k="Action"><ActionBadge action={e.action} /></Row>
              <Row k="Risk"><RiskBadge level={e.risk_level} /> score {e.risk_score}/100</Row>
              <Row k="Detected entities">{e.entity_types.length ? <span className="flex flex-wrap gap-1">{e.entity_types.map((t) => <Chip key={t}>{t}</Chip>)}</span> : "none"}</Row>
              <Row k="Fail-closed">{e.failed_closed ? <span className="font-medium text-red-600">Yes: {e.fail_closed_reason}</span> : "No"}</Row>
              <Row k="Policy">{e.policy_id}</Row>
              <Row k="Provider / model">{e.provider ?? "-"} / {e.model ?? "-"}</Row>
              <Row k="Application">{e.application ?? "-"}</Row>
              <Row k="Caller">{e.user_id ? `user ${e.user_id}` : e.api_key_id ? `API key ${e.api_key_id}` : "-"}</Row>
              <Row k="Request id">{e.request_id}</Row>
              <Row k="Detector version">{e.detector_version}</Row>
              <Row k="Scan latency">{e.latency_ms} ms</Row>
            </dl>
          </Card>
        </>
      )}
    </Shell>
  );
}
