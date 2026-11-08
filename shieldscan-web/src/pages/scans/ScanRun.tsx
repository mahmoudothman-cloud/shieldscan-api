/**
 * /scans/:scanId — the scan run page of the approved design: status
 * header with cancel, one card per engine (from the polled detail), the
 * live event feed (SSE over fetch, replayed from the start so a reload
 * shows history), and the severity summary once findings exist.
 */

import { useEffect, useRef, useState } from "react";
import { Link, useParams } from "react-router";
import { useOrgId } from "@/lib/auth";
import { ACTIVE_STATUSES, useCancelScan, useScan } from "@/lib/queries";
import { readSse } from "@/lib/sse";
import type { ProgressEvent, ScanJobDetail, Severity } from "@/lib/types";
import { duration, relTime, scanTypeLabel } from "@/lib/format";
import { cx } from "@/lib/cx";
import { Alert, Button, Card, SeverityBadge, Spinner, StatusBadge } from "@/components/ui";

const SEVS: Severity[] = ["critical", "high", "medium", "low", "info"];

export default function ScanRun() {
  const { scanId = "" } = useParams();
  const orgId = useOrgId();
  const scan = useScan(orgId, scanId);
  const cancel = useCancelScan(orgId);

  if (scan.isPending) return <Spinner label="Loading scan" />;
  if (scan.isError)
    return <Alert tone="error">This scan doesn't exist or you don't have access to it.</Alert>;
  const s = scan.data;
  const active = ACTIVE_STATUSES.includes(s.status);
  const done = s.jobs.filter((j) => ["completed", "failed", "canceled"].includes(j.status)).length;
  const pct = s.jobs.length ? Math.round((done / s.jobs.length) * 100) : 0;

  return (
    <div className="flex flex-col gap-6">
      <header className="flex items-start justify-between gap-4">
        <div>
          <Link to={`/projects/${s.project_id}`} className="text-sm text-brand">
            ← {s.project_name}
          </Link>
          <h1 className="mt-1 flex items-center gap-3 text-2xl font-semibold text-ink">
            {scanTypeLabel(s.scan_type)} scan
            <StatusBadge status={s.status} />
          </h1>
          <p className="mt-1 text-sm text-ink-3">
            {s.target_url} · started {relTime(s.started_at ?? s.created_at)}
            {s.completed_at ? ` · finished ${relTime(s.completed_at)}` : ""}
            {s.ai_pipeline_degraded ? " · AI analysis degraded (fallback used)" : ""}
          </p>
        </div>
        <div className="flex items-center gap-2">
          {(s.status === "completed" || s.status === "partial") && s.vulnerability_count > 0 ? (
            <Link to={`/vulnerabilities?scan_id=${s.id}`}>
              <Button variant="secondary">View {s.vulnerability_count} vulnerabilities</Button>
            </Link>
          ) : null}
          {active && (
            <Button
              variant="danger"
              size="sm"
              loading={cancel.isPending}
              onClick={() => cancel.mutate(s.id)}
            >
              Cancel scan
            </Button>
          )}
        </div>
      </header>

      {s.error_message && <Alert tone="error">{s.error_message}</Alert>}

      <div className="rounded-card border border-line bg-paper p-4">
        <div className="flex items-center justify-between text-sm">
          <span className="font-medium text-ink">
            {active
              ? `Running — ${done} of ${s.jobs.length} engines finished`
              : `${done} of ${s.jobs.length} engines finished`}
          </span>
          <span className="text-ink-3">
            {s.raw_finding_count} raw findings → {s.vulnerability_count} unique
          </span>
        </div>
        <div
          className="mt-2 h-2 overflow-hidden rounded-full bg-wash-2"
          role="progressbar"
          aria-valuenow={pct}
          aria-valuemin={0}
          aria-valuemax={100}
        >
          <div
            className={cx(
              "h-full rounded-full transition-all",
              active ? "bg-brand" : "bg-ok-strong",
            )}
            style={{ width: `${pct}%` }}
          />
        </div>
        {s.status === "analyzing" && (
          <p className="mt-2 text-xs text-ink-3">
            Engines are done. The AI layer is now deduplicating, scoring and writing fixes — usually
            one to three minutes.
          </p>
        )}
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        <div className="flex flex-col gap-6 lg:col-span-2">
          <Card title="Engines">
            <ul className="grid gap-3 sm:grid-cols-2">
              {s.jobs.map((j) => (
                <EngineCard key={j.id} job={j} />
              ))}
            </ul>
          </Card>
          {s.vulnerability_count > 0 && (
            <Card title="Findings by severity">
              <div className="flex flex-wrap gap-4">
                {SEVS.map((sev) => (
                  <div key={sev} className="flex items-center gap-2">
                    <SeverityBadge severity={sev} />
                    <span className="font-display text-xl font-semibold text-ink tabular-nums">
                      {s.severity_counts[sev]}
                    </span>
                  </div>
                ))}
              </div>
            </Card>
          )}
        </div>
        <LiveFeed key={s.id} orgId={orgId} scanId={s.id} active={active} />
      </div>
    </div>
  );
}

function EngineCard({ job }: { job: ScanJobDetail }) {
  const tone =
    job.status === "completed"
      ? "border-ok/30"
      : job.status === "failed"
        ? "border-critical/40"
        : job.status === "running"
          ? "border-brand/50"
          : "border-line";
  return (
    <li className={cx("rounded-control border bg-paper p-3", tone)}>
      <div className="flex items-center justify-between">
        <span className="font-medium text-ink">{job.engine}</span>
        <StatusBadge status={job.status} />
      </div>
      <p className="mt-1 truncate text-xs text-ink-3" title={job.target_url}>
        {job.target_url}
      </p>
      <p className="mt-2 text-xs text-ink-3">
        {job.status === "completed" || job.status === "failed"
          ? `${job.finding_count} findings · ${duration(job.duration_ms)}`
          : job.status === "running"
            ? "working…"
            : "waiting for a worker"}
      </p>
      {job.error_message && <p className="mt-1 text-xs text-critical">{job.error_message}</p>}
    </li>
  );
}

// ---------------------------------------------------------------- live feed

function describe(e: ProgressEvent): string {
  switch (e.event_type) {
    case "job_started":
      return `${e.engine} started on ${e.target ?? ""}`.trim();
    case "job_completed":
      return `${e.engine} finished — ${e.finding_count ?? 0} findings in ${duration(e.duration_ms)}`;
    case "job_failed":
      return `${e.engine} failed: ${e.error ?? "unknown error"}`;
    case "recon_started":
      return `Recon started for ${e.domain ?? ""}`.trim();
    case "subdomains_discovered":
      return `${e.count ?? 0} subdomains discovered`;
    case "liveness_probed":
      return `${e.count ?? 0} live hosts`;
    case "recon_completed":
      return `Recon done — ${e.live_count ?? 0} live targets`;
    default:
      return e.event_type.replaceAll("_", " ");
  }
}

function LiveFeed({ orgId, scanId, active }: { orgId: string; scanId: string; active: boolean }) {
  const [events, setEvents] = useState<ProgressEvent[]>([]);
  const [state, setState] = useState<"connecting" | "live" | "closed" | "error">("connecting");
  const seen = useRef(new Set<string>());
  const bottom = useRef<HTMLDivElement>(null);

  const activeRef = useRef(active);
  useEffect(() => {
    activeRef.current = active;
  }, [active]);
  const lastId = useRef<string>("-");

  // Connect; while the scan is still active, reconnect after a pause
  // from the last event id (the worker closes idle streams and proxies
  // time out long ones). Terminal scans read the replay once.
  useEffect(() => {
    const ctrl = new AbortController();
    const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));
    void (async () => {
      for (let attempt = 0; !ctrl.signal.aborted; attempt++) {
        await readSse(`/v1/orgs/${orgId}/scans/${scanId}/progress`, {
          lastEventId: lastId.current,
          signal: ctrl.signal,
          onOpen: () => setState("live"),
          onError: () => setState("error"),
          onMessage: (m) => {
            if (m.id) lastId.current = m.id;
            try {
              const payload = JSON.parse(m.data) as Record<string, unknown>;
              const eventType =
                typeof payload.event_type === "string" ? payload.event_type : m.event;
              const ts = typeof payload.timestamp === "string" ? payload.timestamp : "";
              const id = m.id ?? `${ts}-${eventType}`;
              if (seen.current.has(id)) return;
              seen.current.add(id);
              const next = { ...payload, id, event_type: eventType } as ProgressEvent;
              setEvents((prev) => [...prev, next].slice(-300));
            } catch {
              /* ignore non-JSON frames */
            }
          },
        });
        if (ctrl.signal.aborted || !activeRef.current) break;
        setState("connecting");
        await sleep(Math.min(15_000, 2_000 * (attempt + 1)));
      }
      if (!ctrl.signal.aborted) setState((st) => (st === "error" ? st : "closed"));
    })();
    return () => ctrl.abort();
  }, [orgId, scanId]);

  useEffect(() => {
    bottom.current?.scrollIntoView({ block: "nearest" });
  }, [events.length]);

  return (
    <Card
      title="Live feed"
      action={
        <span className="text-xs text-ink-3">
          {state === "live" && active
            ? "● live"
            : state === "connecting"
              ? "connecting…"
              : state === "error"
                ? "stream unavailable — list still updates"
                : "complete"}
        </span>
      }
    >
      <ol className="max-h-[32rem] overflow-y-auto font-mono text-xs leading-5">
        {events.length === 0 && <li className="text-ink-3">Waiting for the first worker event…</li>}
        {events.map((e) => (
          <li
            key={e.id}
            className={cx(
              "flex gap-3 border-b border-line-2 py-1 last:border-0",
              e.event_type === "job_failed" && "text-critical",
            )}
          >
            <span className="shrink-0 text-muted">
              {e.timestamp ? new Date(e.timestamp).toLocaleTimeString() : ""}
            </span>
            <span className="text-ink">{describe(e)}</span>
          </li>
        ))}
        <div ref={bottom} />
      </ol>
    </Card>
  );
}
