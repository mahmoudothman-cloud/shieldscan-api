/**
 * /dashboard — the approved design v1.0 home: greeting line, open
 * vulnerabilities by severity, noise-removed tile, recent scans, and
 * the "needs you" list. Compliance posture and tool health cards arrive
 * with their pages.
 */

import { Link } from "react-router";
import { useAuth, useOrgId } from "@/lib/auth";
import { useOrgScans, useOrgSummary, useProjects } from "@/lib/queries";
import type { ScanListItem, Severity } from "@/lib/types";
import { Alert, Button, Card, Empty, Spinner, StatusBadge } from "@/components/ui";
import { cx } from "@/lib/cx";

function greeting(name: string | undefined): string {
  const h = new Date().getHours();
  const part = h < 12 ? "Good morning" : h < 18 ? "Good afternoon" : "Good evening";
  return name ? `${part}, ${name.split(" ")[0]}` : part;
}

function relTime(iso: string | null): string {
  if (!iso) return "—";
  const diff = Date.now() - new Date(iso).getTime();
  const m = Math.round(diff / 60_000);
  if (m < 1) return "just now";
  if (m < 60) return `${m} min ago`;
  const h = Math.round(m / 60);
  if (h < 48) return `${h} h ago`;
  return `${Math.round(h / 24)} d ago`;
}

const SEV_ORDER: Severity[] = ["critical", "high", "medium", "low"];
const SEV_TEXT: Record<Severity, string> = {
  critical: "text-critical",
  high: "text-high",
  medium: "text-medium",
  low: "text-low",
  info: "text-muted",
};

export default function Dashboard() {
  const { me } = useAuth();
  const orgId = useOrgId();
  const summary = useOrgSummary(orgId);
  const scans = useOrgScans(orgId, { per_page: 8 });
  const projects = useProjects(orgId);

  if (summary.isPending) return <Spinner label="Loading your dashboard" />;
  if (summary.isError)
    return <Alert tone="error">Couldn't load the dashboard summary. Try refreshing.</Alert>;

  const s = summary.data;
  const last = s.last_completed_scan;
  const noise =
    last && last.raw_finding_count > 0
      ? Math.round((1 - last.vulnerability_count / last.raw_finding_count) * 100)
      : null;
  const unverified = projects.data?.items.filter((p) => !p.domain_verified && !p.archived_at) ?? [];

  return (
    <div className="flex flex-col gap-6">
      <header className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold text-ink">{greeting(me?.user?.full_name)}</h1>
          <p className="mt-1 text-sm text-ink-3">
            {s.projects.total} {s.projects.total === 1 ? "project" : "projects"}
            {last ? ` · last scan ${relTime(last.completed_at)}` : " · no scans yet"}
            {s.scans.active > 0 ? ` · ${s.scans.active} running` : ""}
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="secondary" disabled title="Projects page arrives in the next slice">
            Add project
          </Button>
          <Button disabled title="Scan run arrives in the next slice">
            Run a scan
          </Button>
        </div>
      </header>

      <section className="grid grid-cols-2 gap-4 lg:grid-cols-5" aria-label="Open vulnerabilities">
        {SEV_ORDER.map((sev) => (
          <div key={sev} className="rounded-card border border-line bg-paper p-4">
            <p className="text-xs font-medium uppercase tracking-wide text-ink-3">{sev}</p>
            <p className={cx("mt-1 font-display text-3xl font-semibold", SEV_TEXT[sev])}>
              {s.open_vulnerabilities[sev] + (sev === "low" ? s.open_vulnerabilities.info : 0)}
            </p>
            <p className="mt-1 text-xs text-muted">
              {sev === "critical" && s.open_vulnerabilities.corroborated > 0
                ? `${s.open_vulnerabilities.corroborated} corroborated`
                : sev === "low"
                  ? "incl. info"
                  : " "}
            </p>
          </div>
        ))}
        <div className="rounded-card border border-line bg-paper p-4">
          <p className="text-xs font-medium uppercase tracking-wide text-ink-3">Noise removed</p>
          <p className="mt-1 font-display text-3xl font-semibold text-brand">
            {noise === null ? "—" : `${noise}%`}
          </p>
          <p className="mt-1 text-xs text-muted">
            {last
              ? `${last.raw_finding_count} raw → ${last.vulnerability_count} unique`
              : "after your first scan"}
          </p>
        </div>
      </section>

      <div className="grid gap-6 lg:grid-cols-3">
        <Card
          title="Recent scans"
          className="lg:col-span-2"
          action={
            <span className="text-xs text-muted">
              {s.scans.total} total · {s.scans.completed_30d} finished in 30 days
            </span>
          }
        >
          {scans.isPending ? (
            <Spinner />
          ) : !scans.data || scans.data.items.length === 0 ? (
            <Empty
              title="No scans yet"
              body="Add a target and run your first full scan — all 14 engines, free on this plan."
            />
          ) : (
            <ScanTable items={scans.data.items} />
          )}
        </Card>

        <Card title="Needs you">
          {projects.isPending ? (
            <Spinner />
          ) : unverified.length === 0 && s.open_vulnerabilities.critical === 0 ? (
            <p className="text-sm text-ink-3">
              Nothing waiting on you. Your targets are verified and no critical issue is open.
            </p>
          ) : (
            <ul className="flex flex-col gap-3 text-sm">
              {unverified.map((p) => (
                <li
                  key={p.id}
                  className="rounded-control border border-warn/40 bg-high-wash p-3 text-ink"
                >
                  <strong>{p.name}</strong> is not verified — only quick scans can run. Add the DNS
                  record to unlock full scans.
                </li>
              ))}
              {s.open_vulnerabilities.critical > 0 && (
                <li className="rounded-control border border-critical/30 bg-critical-wash p-3 text-ink">
                  {s.open_vulnerabilities.critical} critical{" "}
                  {s.open_vulnerabilities.critical === 1
                    ? "vulnerability is"
                    : "vulnerabilities are"}{" "}
                  open
                  {s.open_vulnerabilities.corroborated > 0
                    ? `, ${s.open_vulnerabilities.corroborated} confirmed by more than one engine`
                    : ""}
                  .
                </li>
              )}
            </ul>
          )}
        </Card>
      </div>
    </div>
  );
}

function ScanTable({ items }: { items: ScanListItem[] }) {
  return (
    <table className="w-full text-sm">
      <thead>
        <tr className="text-left text-xs font-medium uppercase tracking-wide text-ink-3">
          <th className="pb-2">Project</th>
          <th className="pb-2">Type</th>
          <th className="pb-2">Status</th>
          <th className="pb-2 text-right">Findings</th>
          <th className="pb-2 text-right">When</th>
        </tr>
      </thead>
      <tbody>
        {items.map((sc) => (
          <tr key={sc.id} className="border-t border-line-2">
            <td className="py-2.5 font-medium text-ink">
              <Link to={`/scans/${sc.id}`} className="hover:text-brand">
                {sc.project_name}
              </Link>
            </td>
            <td className="py-2.5 text-ink-3">{sc.scan_type.replaceAll("_", " ")}</td>
            <td className="py-2.5">
              <StatusBadge status={sc.status} detail={`${sc.jobs_terminal}/${sc.jobs_total}`} />
            </td>
            <td className="py-2.5 text-right tabular-nums">{sc.vulnerability_count}</td>
            <td className="py-2.5 text-right text-ink-3">
              {relTime(sc.completed_at ?? sc.created_at)}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
