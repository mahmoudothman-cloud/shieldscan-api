/**
 * /q/:slug — the emailed, token-addressed result. Polls while running,
 * then shows the grade, the top findings in full and only the count of
 * the rest; the register CTA carries the slug so the account pre-fills.
 * Says plainly that the grade covers passive checks only.
 */

import { Link, useParams } from "react-router";
import { useQuickScanResult } from "@/lib/queries";
import { ApiError } from "@/lib/api";
import type { Severity } from "@/lib/types";
import { relTime } from "@/lib/format";
import { cx } from "@/lib/cx";
import { Alert, Button, SeverityBadge, Spinner } from "@/components/ui";
import { PublicLayout } from "./PublicLayout";

const SEVS: Severity[] = ["critical", "high", "medium", "low", "info"];
const GRADE_TONE: Record<string, string> = {
  A: "bg-ok-wash text-ok border-ok/30",
  B: "bg-ok-wash text-ok border-ok/30",
  C: "bg-medium-wash text-medium border-medium/30",
  D: "bg-high-wash text-high border-high/30",
  F: "bg-critical-wash text-critical border-critical/30",
};

export default function QuickScanResult() {
  const { slug = "" } = useParams();
  const result = useQuickScanResult(slug);

  return (
    <PublicLayout>
      {result.isPending ? (
        <Spinner label="Loading your result" />
      ) : result.isError ? (
        <Alert tone="error">
          {result.error instanceof ApiError && result.error.status === 404
            ? "This result link isn't valid. Check the link in your email, or run a new quick scan."
            : "Couldn't load the result."}
        </Alert>
      ) : (
        <Body r={result.data} />
      )}
    </PublicLayout>
  );
}

function daysUntil(iso: string): string {
  const d = Math.max(0, Math.round((new Date(iso).getTime() - Date.now()) / 86_400_000));
  return d === 0 ? "less than a day" : d === 1 ? "1 day" : `${d} days`;
}

function Body({ r }: { r: NonNullable<ReturnType<typeof useQuickScanResult>["data"]> }) {
  const live = ["queued", "reconning", "running", "analyzing"].includes(r.status);
  const registerHref = `/register?from=${r.slug}`;

  if (r.status === "expired") {
    return (
      <div className="mx-auto max-w-xl text-center">
        <h1 className="text-2xl font-semibold text-ink">This result has expired</h1>
        <p className="mt-2 text-sm text-ink-3">
          Quick-scan results are kept for 7 days. Run a new one, or create an account to keep every
          scan.
        </p>
        <div className="mt-6 flex justify-center gap-3">
          <Link to="/quick-scan">
            <Button variant="secondary">New quick scan</Button>
          </Link>
          <Link to={registerHref}>
            <Button>Create account</Button>
          </Link>
        </div>
      </div>
    );
  }

  if (live) {
    const pct = r.engines_total ? Math.round((r.engines_finished / r.engines_total) * 100) : 5;
    return (
      <div className="mx-auto max-w-xl">
        <p className="text-xs font-semibold uppercase tracking-wider text-brand">
          Quick scan · {r.domain}
        </p>
        <h1 className="mt-2 text-2xl font-semibold text-ink">Scanning {r.target_url}</h1>
        <p className="mt-2 text-sm text-ink-3">
          {r.engines_finished} of {r.engines_total} checks finished · started{" "}
          {relTime(r.created_at)} · usually about two minutes. This page updates by itself; the link
          in your email brings you back.
        </p>
        <div
          className="mt-6 h-2 overflow-hidden rounded-full bg-wash-2"
          role="progressbar"
          aria-valuenow={pct}
          aria-valuemin={0}
          aria-valuemax={100}
        >
          <div
            className="h-full rounded-full bg-brand transition-all"
            style={{ width: `${Math.max(pct, 5)}%` }}
          />
        </div>
      </div>
    );
  }

  const failed = r.status === "failed" || r.status === "canceled";
  return (
    <div className="mx-auto max-w-3xl">
      <p className="text-xs font-semibold uppercase tracking-wider text-brand">
        Quick scan · {r.domain}
      </p>
      <div className="mt-2 flex flex-wrap items-center gap-6">
        {r.grade && (
          <div
            className={cx(
              "flex size-24 flex-col items-center justify-center rounded-card border font-display",
              GRADE_TONE[r.grade] ?? "",
            )}
          >
            <span className="text-5xl font-semibold leading-none">{r.grade}</span>
            <span className="mt-1 text-xs">{r.score}/100</span>
          </div>
        )}
        <div className="min-w-0 flex-1">
          <h1 className="text-2xl font-semibold text-ink">
            {failed
              ? "The scan couldn't finish"
              : r.findings_by_severity.total === 0
                ? "Nothing passive to report"
                : `${r.findings_by_severity.total} findings on ${r.domain}`}
          </h1>
          <p className="mt-1 text-sm text-ink-3">
            {r.status === "partial" ? "One check failed; the grade reflects what did run. " : ""}
            Finished {relTime(r.completed_at)} · passive checks only — headers, TLS, exposed files,
            fingerprints.
          </p>
          <div className="mt-2 flex flex-wrap gap-2">
            {SEVS.filter((s) => r.findings_by_severity[s] > 0).map((s) => (
              <span key={s} className="inline-flex items-center gap-1 text-xs text-ink-3">
                <SeverityBadge severity={s} /> {r.findings_by_severity[s]}
              </span>
            ))}
          </div>
        </div>
      </div>

      <Alert tone="info">
        <strong>What this grade does not cover.</strong> A passive scan cannot test for injection,
        broken authentication, or access-control flaws — the issues that actually get sites
        breached. On a deliberately vulnerable test site, this quick scan grades A while the full
        scan finds 40 issues including SQL injection. The full scan is free to try after you verify
        the domain.
      </Alert>

      <ol className="mt-6 flex flex-col gap-3">
        {r.findings.map((f, i) => (
          <li key={i} className="rounded-card border border-line bg-paper p-4">
            <div className="flex items-center gap-3">
              <SeverityBadge severity={f.severity} />
              <h2 className="font-medium text-ink">{f.title}</h2>
              <span className="ml-auto text-xs text-ink-3">{f.engine}</span>
            </div>
            {f.summary && <p className="mt-2 text-sm text-ink-3">{f.summary}</p>}
            {f.target_url && (
              <p className="mt-1 break-all font-mono text-xs text-muted">{f.target_url}</p>
            )}
          </li>
        ))}
      </ol>

      {r.hidden_count > 0 && (
        <div className="relative mt-3 rounded-card border border-dashed border-line bg-paper p-6 text-center">
          <p className="font-medium text-ink">
            {r.hidden_count} more {r.hidden_count === 1 ? "finding" : "findings"} on this site
          </p>
          <p className="mt-1 text-sm text-ink-3">
            Create a free account and run this scan again from the dashboard: every finding comes
            with the AI explanation and fix, and you can start the full 14-engine scan once the
            domain is verified.
          </p>
          <Link to={registerHref} className="mt-4 inline-block">
            <Button>Create account — it's free</Button>
          </Link>
        </div>
      )}
      {r.hidden_count === 0 && (
        <div className="mt-6 text-center">
          <Link to={registerHref}>
            <Button>Create account and run the full scan</Button>
          </Link>
        </div>
      )}
      <p className="mt-6 text-center text-xs text-muted">
        This link is private to you and expires in {daysUntil(r.expires_at)}.
      </p>
    </div>
  );
}
