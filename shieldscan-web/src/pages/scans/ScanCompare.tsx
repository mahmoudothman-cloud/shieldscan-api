import { useState } from "react";
import { Link } from "react-router";

import { Alert, Card, Select, SeverityBadge, Spinner } from "@/components/ui";
import { ApiError } from "@/lib/api";
import { cx } from "@/lib/cx";
import { relTime, scanTypeLabel } from "@/lib/format";
import { useProjectScans, useScanComparison } from "@/lib/queries";
import type { ComparedFinding, ScanComparison, ScanDetailResponse } from "@/lib/types";

/** "What changed since the last scan" — the diff on identity links
 *  (previous_id / superseded_by_id / regression), so it agrees with the
 *  open counts and the CLI's PR comment. Baseline defaults to the previous
 *  finished scan of the same type; any earlier finished scan can be picked. */
export function ScanCompare({ scan }: { scan: ScanDetailResponse }) {
  const [baseline, setBaseline] = useState<string | null>(null);
  const terminal = scan.status === "completed" || scan.status === "partial";
  const candidates = useProjectScans(scan.organization_id, scan.project_id, { per_page: 50 });
  const cmp = useScanComparison(scan.organization_id, scan.id, baseline, terminal);

  if (!terminal) return null;
  const noBaseline = cmp.error instanceof ApiError && cmp.error.detail === "no_baseline";
  const options = (candidates.data?.items ?? []).filter(
    (s) =>
      s.id !== scan.id &&
      (s.status === "completed" || s.status === "partial") &&
      new Date(s.created_at) < new Date(scan.created_at),
  );

  return (
    <Card
      title="Changes since the previous scan"
      action={
        options.length > 1 ? (
          <Select
            value={baseline ?? ""}
            onChange={(e) => setBaseline(e.target.value || null)}
            aria-label="Baseline scan"
          >
            <option value="">Previous {scanTypeLabel(scan.scan_type)} scan</option>
            {options.map((s) => (
              <option key={s.id} value={s.id}>
                {scanTypeLabel(s.scan_type)} · {relTime(s.created_at)}
              </option>
            ))}
          </Select>
        ) : null
      }
    >
      {cmp.isPending && <Spinner label="Comparing" />}
      {noBaseline && (
        <p className="text-sm text-ink-3">
          This is the first finished {scanTypeLabel(scan.scan_type)} scan of this project — nothing
          to compare against yet.
        </p>
      )}
      {cmp.isError && !noBaseline && <Alert tone="error">Couldn't compare these scans.</Alert>}
      {cmp.data && <Diff data={cmp.data} />}
    </Card>
  );
}

const BUCKETS: {
  key: keyof Pick<ScanComparison, "new" | "regressions" | "persisting" | "fixed" | "not_covered">;
  label: string;
  tone: string;
  hint: string;
}[] = [
  { key: "new", label: "New", tone: "text-critical", hint: "Not seen in the baseline." },
  {
    key: "regressions",
    label: "Regressions",
    tone: "text-critical",
    hint: "Had been resolved; found again by this scan.",
  },
  {
    key: "fixed",
    label: "Fixed",
    tone: "text-ok",
    hint: "Open in the baseline, proven gone by this scan.",
  },
  { key: "persisting", label: "Still open", tone: "text-ink-3", hint: "Found by both scans." },
  {
    key: "not_covered",
    label: "Not covered",
    tone: "text-warn",
    hint: "Open in the baseline; this scan did not look for it (narrower scope or an engine failed), so nothing is known.",
  },
];

function Diff({ data }: { data: ScanComparison }) {
  const [open, setOpen] = useState<string | null>(
    data.summary.new + data.summary.regressions > 0
      ? "new"
      : data.summary.fixed > 0
        ? "fixed"
        : null,
  );
  return (
    <div className="flex flex-col gap-3">
      <p className="text-sm text-ink-3">
        Compared with the {scanTypeLabel(data.baseline.scan_type)} scan from{" "}
        {relTime(data.baseline.created_at)}
        {data.summary.triaged > 0 && ` · ${data.summary.triaged} triaged finding(s) hidden`}
        {data.summary.truncated && " · lists truncated"}
      </p>
      {!data.summary.scope_covered && (
        <Alert tone="info">
          This scan ran with a narrower scope than the baseline, so "not covered" is expected and
          nothing in it was auto-resolved.
        </Alert>
      )}
      {data.summary.scope_covered && !data.summary.scope_known && (
        <p className="text-xs text-ink-3">
          One of these scans predates scope recording, so coverage between them is not known.
        </p>
      )}
      <ul className="grid gap-2 sm:grid-cols-5" aria-label="Change summary">
        {BUCKETS.map((b) => {
          const n = data.summary[b.key];
          const active = open === b.key;
          return (
            <li key={b.key}>
              <button
                type="button"
                title={b.hint}
                onClick={() => setOpen(active ? null : b.key)}
                disabled={n === 0}
                className={cx(
                  "w-full rounded-control border px-3 py-2 text-left",
                  active ? "border-brand bg-brand-wash" : "border-line",
                  n === 0 && "opacity-60",
                )}
              >
                <div
                  className={cx(
                    "font-display text-xl font-semibold tabular-nums",
                    n > 0 ? b.tone : "text-ink-3",
                  )}
                >
                  {n}
                </div>
                <div className="text-xs text-ink-3">{b.label}</div>
              </button>
            </li>
          );
        })}
      </ul>
      {open && (
        <FindingList
          items={data[open as "new" | "regressions" | "persisting" | "fixed" | "not_covered"]}
          hint={BUCKETS.find((b) => b.key === open)?.hint ?? ""}
        />
      )}
    </div>
  );
}

function FindingList({ items, hint }: { items: ComparedFinding[]; hint: string }) {
  return (
    <div>
      <p className="mb-1 text-xs text-ink-3">{hint}</p>
      <ul className="divide-y divide-line">
        {items.map((f) => (
          <li key={f.id} className="flex items-center gap-3 py-1.5 text-sm">
            <SeverityBadge severity={f.severity} />
            <Link
              to={`/vulnerabilities/${f.id}`}
              className="min-w-0 flex-1 truncate text-ink hover:underline"
            >
              {f.title}
            </Link>
            <span className="shrink-0 text-xs text-ink-3">
              {f.regression && "regression · "}
              {f.first_seen_at && `first seen ${relTime(f.first_seen_at)}`}
              {f.resolved_at && ` · resolved ${relTime(f.resolved_at)}`}
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}
