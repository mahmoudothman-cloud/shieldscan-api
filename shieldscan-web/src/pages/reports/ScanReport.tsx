/**
 * /scans/:scanId/report — the deliverable for people who were not in
 * the room: the AI executive summary, the severity picture, and the
 * downloads (PDF for humans, SARIF for GitHub code scanning, JSON for
 * everything else). Available once a scan is terminal.
 */

import { Link, useParams } from "react-router";
import { Download, FileJson, FileText, ShieldCheck } from "lucide-react";
import { useOrgId } from "@/lib/auth";
import {
  useDownloadInline,
  useExecutiveReport,
  useReportManifest,
  useRequestPdf,
  useScan,
} from "@/lib/queries";
import { ApiError } from "@/lib/api";
import type { Severity } from "@/lib/types";
import { relTime, scanTypeLabel } from "@/lib/format";
import { Alert, Button, Card, SeverityBadge, Spinner } from "@/components/ui";
import { Markdown } from "@/components/Markdown";

const SEVS: Severity[] = ["critical", "high", "medium", "low", "info"];

export default function ScanReport() {
  const { scanId = "" } = useParams();
  const orgId = useOrgId();
  const scan = useScan(orgId, scanId);
  const manifest = useReportManifest(orgId, scanId);
  const ready = manifest.isSuccess;
  const executive = useExecutiveReport(
    orgId,
    scanId,
    ready && (scan.data?.executive_summary_available ?? false),
  );
  const pdf = useRequestPdf(orgId, scanId);
  const inline = useDownloadInline(orgId, scanId);

  if (scan.isPending || manifest.isPending) return <Spinner label="Preparing report" />;
  if (scan.isError)
    return <Alert tone="error">This scan doesn't exist or you don't have access to it.</Alert>;
  const s = scan.data;

  if (manifest.isError) {
    const notReady = manifest.error instanceof ApiError && manifest.error.status === 409;
    return (
      <div className="flex flex-col gap-4">
        <Back s={s} />
        <Alert tone={notReady ? "info" : "error"}>
          {notReady
            ? "The report is available once the scan finishes. This one is still " + s.status + "."
            : "Couldn't load the report."}
        </Alert>
      </div>
    );
  }

  const total = SEVS.reduce((n, sev) => n + s.severity_counts[sev], 0);

  return (
    <div className="flex flex-col gap-6">
      <header className="flex items-start justify-between gap-4">
        <div>
          <Back s={s} />
          <h1 className="mt-1 text-2xl font-semibold text-ink">Security report</h1>
          <p className="mt-1 text-sm text-ink-3">
            {s.project_name} · {s.target_url} · {scanTypeLabel(s.scan_type)} scan finished{" "}
            {relTime(s.completed_at)} ·{" "}
            {s.status === "partial" ? "partial (one or more engines failed)" : "complete"}
          </p>
        </div>
        <div className="flex gap-2">
          <Button
            onClick={() =>
              void pdf.mutateAsync().then((r) => window.open(r.download_url, "_blank", "noopener"))
            }
            loading={pdf.isPending}
          >
            <FileText className="size-4" aria-hidden />{" "}
            {manifest.data.pdf?.generated ? "Download PDF" : "Generate PDF"}
          </Button>
        </div>
      </header>

      {pdf.isError && <Alert tone="error">Couldn't generate the PDF. Try again in a minute.</Alert>}
      {pdf.isSuccess && (
        <Alert tone="success">
          PDF ready ({Math.round(pdf.data.size_bytes / 1024)} KB). The link opened in a new tab and
          stays valid for one hour —{" "}
          <a href={pdf.data.download_url} target="_blank" rel="noreferrer" className="underline">
            open again
          </a>
          .
        </Alert>
      )}

      <div className="grid gap-6 lg:grid-cols-3">
        <div className="flex flex-col gap-6 lg:col-span-2">
          <Card title="Executive summary">
            {!s.executive_summary_available ? (
              <p className="text-sm text-ink-3">
                No executive summary was generated for this scan
                {s.ai_pipeline_degraded ? " (the AI layer was degraded during the run)" : ""}. The
                PDF still carries every finding.
              </p>
            ) : executive.isPending ? (
              <Spinner />
            ) : executive.data?.executive_summary ? (
              <Markdown source={executive.data.executive_summary} />
            ) : (
              <p className="text-sm text-ink-3">Summary unavailable.</p>
            )}
          </Card>
        </div>

        <div className="flex flex-col gap-6">
          <Card title="Findings">
            <ul className="flex flex-col gap-2">
              {SEVS.map((sev) => (
                <li key={sev} className="flex items-center justify-between text-sm">
                  <SeverityBadge severity={sev} />
                  <span className="font-display text-lg font-semibold tabular-nums text-ink">
                    {s.severity_counts[sev]}
                  </span>
                </li>
              ))}
              <li className="mt-1 flex items-center justify-between border-t border-line-2 pt-2 text-sm">
                <span className="text-ink-3">{s.raw_finding_count} raw → unique</span>
                <span className="font-display text-lg font-semibold tabular-nums text-ink">
                  {total}
                </span>
              </li>
            </ul>
            <Link
              to={`/vulnerabilities?scan_id=${s.id}&status=`}
              className="mt-3 inline-block text-sm text-brand"
            >
              Open in the explorer →
            </Link>
          </Card>

          <Card title="Machine-readable">
            <div className="flex flex-col gap-2">
              <Button
                variant="secondary"
                onClick={() => inline.mutate("sarif")}
                loading={inline.isPending && inline.variables === "sarif"}
              >
                <ShieldCheck className="size-4" aria-hidden /> SARIF 2.1.0 — GitHub code scanning
              </Button>
              <Button
                variant="secondary"
                onClick={() => inline.mutate("json")}
                loading={inline.isPending && inline.variables === "json"}
              >
                <FileJson className="size-4" aria-hidden /> JSON — full fidelity
              </Button>
              {inline.isError && <Alert tone="error">Download failed.</Alert>}
              <p className="text-xs text-ink-3">
                <Download className="mr-1 inline size-3" aria-hidden />
                Same data the CLI and the GitHub Action use (M13).
              </p>
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
}

function Back({ s }: { s: { id: string; project_name: string } }) {
  return (
    <Link to={`/scans/${s.id}`} className="text-sm text-brand">
      ← Scan of {s.project_name}
    </Link>
  );
}
