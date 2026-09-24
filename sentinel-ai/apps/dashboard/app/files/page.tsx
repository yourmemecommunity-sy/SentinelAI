"use client";
import { FileScanner } from "@/components/dashboard/FileScanner";
import { Shell } from "@/components/dashboard/Shell";
import { EventsTable } from "@/components/security-events/EventsTable";
import { Card, Loading, Notice } from "@/components/ui/primitives";
import { useApi } from "@/hooks/useApi";
import type { EventsPage } from "@/types/api";

export default function FilesPage() {
  const { data, error, loading, reload } = useApi<EventsPage>("events?limit=15&event_type=file_scan");
  return (
    <Shell title="File scan">
      <FileScanner onScanned={reload} />
      <Card title="Recent file scans">
        {error && <Notice>{error}</Notice>}
        {loading && !data && <Loading />}
        {data && <EventsTable events={data.events} empty="No files scanned yet." />}
      </Card>
    </Shell>
  );
}
