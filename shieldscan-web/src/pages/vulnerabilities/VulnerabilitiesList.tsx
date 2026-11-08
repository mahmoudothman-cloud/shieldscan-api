/**
 * /vulnerabilities — the explorer. Filters live in the URL so a filtered
 * view is shareable and the scan page can deep-link (`?scan_id=`).
 */

import { Link, useSearchParams } from "react-router";
import { useOrgId } from "@/lib/auth";
import { useProjects, useVulnerabilities } from "@/lib/queries";
import type { EngineCategory, Severity, VulnerabilityStatus } from "@/lib/types";
import { relTime } from "@/lib/format";
import { Alert, Card, Empty, Select, SeverityBadge, Spinner } from "@/components/ui";
import { cx } from "@/lib/cx";
import { STATUS_LABEL } from "@/lib/labels";
import { Pager } from "@/components/Pager";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];
const STATUSES: Array<{ value: VulnerabilityStatus | ""; label: string }> = [
  { value: "open", label: "Open" },
  { value: "resolved", label: "Resolved" },
  { value: "false_positive", label: "False positive" },
  { value: "accepted_risk", label: "Accepted risk" },
  { value: "", label: "Any status" },
];
const CATEGORIES: Array<{ value: EngineCategory | ""; label: string }> = [
  { value: "", label: "All layers" },
  { value: "dast", label: "DAST" },
  { value: "sast", label: "SAST" },
  { value: "sca", label: "Dependencies" },
  { value: "infrastructure", label: "Infrastructure" },
  { value: "ssl", label: "TLS" },
  { value: "mobile", label: "Mobile" },
  { value: "recon", label: "Recon" },
];

export default function VulnerabilitiesList() {
  const orgId = useOrgId();
  const [params, setParams] = useSearchParams();
  const page = Number(params.get("page") ?? "1") || 1;
  const filters = {
    page,
    severity: params.get("severity") ?? "",
    status: params.has("status") ? (params.get("status") ?? "") : "open",
    engine_category: params.get("engine_category") ?? "",
    scan_id: params.get("scan_id") ?? "",
    project_id: params.get("project_id") ?? "",
    sort: params.get("sort") ?? "-severity_score",
  };
  const vulns = useVulnerabilities(orgId, filters);
  const projects = useProjects(orgId);

  function set(key: string, value: string) {
    const next = new URLSearchParams(params);
    if (value === "" && key !== "status") next.delete(key);
    else next.set(key, value);
    next.delete("page");
    setParams(next, { replace: true });
  }
  function toggleSeverity(sev: Severity) {
    const current = filters.severity ? filters.severity.split(",") : [];
    const next = current.includes(sev) ? current.filter((s) => s !== sev) : [...current, sev];
    set("severity", next.join(","));
  }
  const activeSev = new Set(filters.severity ? filters.severity.split(",") : []);

  return (
    <div className="flex flex-col gap-6">
      <header className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold text-ink">Vulnerabilities</h1>
          <p className="mt-1 text-sm text-ink-3">
            Deduplicated and scored across every engine. Each row is one real issue, not one tool's
            report.
          </p>
        </div>
        {filters.scan_id && (
          <Link to={`/scans/${filters.scan_id}`} className="text-sm text-brand">
            Showing one scan · back to the scan
          </Link>
        )}
      </header>

      <div className="flex flex-wrap items-center gap-2">
        {SEVERITIES.map((sev) => (
          <button
            key={sev}
            type="button"
            aria-pressed={activeSev.has(sev)}
            onClick={() => toggleSeverity(sev)}
            className={cx(
              "rounded-full border px-3 py-1 text-xs font-medium capitalize",
              activeSev.has(sev)
                ? "border-ink bg-ink text-white"
                : "border-line bg-paper text-ink-3 hover:border-ink-3",
            )}
          >
            {sev}
          </button>
        ))}
        <span className="mx-1 h-5 w-px bg-line" aria-hidden />
        <Select
          aria-label="Status"
          value={filters.status}
          onChange={(e) => set("status", e.target.value)}
          className="h-8 w-auto text-xs"
        >
          {STATUSES.map((s) => (
            <option key={s.value} value={s.value}>
              {s.label}
            </option>
          ))}
        </Select>
        <Select
          aria-label="Layer"
          value={filters.engine_category}
          onChange={(e) => set("engine_category", e.target.value)}
          className="h-8 w-auto text-xs"
        >
          {CATEGORIES.map((c) => (
            <option key={c.value} value={c.value}>
              {c.label}
            </option>
          ))}
        </Select>
        <Select
          aria-label="Project"
          value={filters.project_id}
          onChange={(e) => set("project_id", e.target.value)}
          className="h-8 w-auto text-xs"
        >
          <option value="">All projects</option>
          {projects.data?.items.map((p) => (
            <option key={p.id} value={p.id}>
              {p.name}
            </option>
          ))}
        </Select>
        <Select
          aria-label="Sort"
          value={filters.sort}
          onChange={(e) => set("sort", e.target.value)}
          className="h-8 w-auto text-xs"
        >
          <option value="-severity_score">Highest score first</option>
          <option value="-created_at">Newest first</option>
          <option value="created_at">Oldest first</option>
          <option value="cwe_id">By CWE</option>
        </Select>
      </div>

      <Card>
        {vulns.isPending ? (
          <Spinner />
        ) : vulns.isError ? (
          <Alert tone="error">Couldn't load vulnerabilities.</Alert>
        ) : vulns.data.items.length === 0 ? (
          <Empty
            title="Nothing matches these filters"
            body={
              filters.status === "open"
                ? "No open vulnerabilities here. Widen the filters to see resolved or accepted ones."
                : undefined
            }
          />
        ) : (
          <>
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-xs font-medium uppercase tracking-wide text-ink-3">
                  <th className="pb-2">Severity</th>
                  <th className="pb-2">Vulnerability</th>
                  <th className="pb-2">Layer</th>
                  <th className="pb-2">Status</th>
                  <th className="pb-2 text-right">Score</th>
                  <th className="pb-2 text-right">Found</th>
                </tr>
              </thead>
              <tbody className={cx(vulns.isPlaceholderData && "opacity-60")}>
                {vulns.data.items.map((v) => (
                  <tr key={v.id} className="border-t border-line-2">
                    <td className="py-2.5">
                      <SeverityBadge severity={v.severity} />
                    </td>
                    <td className="py-2.5">
                      <Link
                        to={`/vulnerabilities/${v.id}`}
                        className="font-medium text-ink hover:text-brand"
                      >
                        {v.title}
                      </Link>
                      <div className="text-xs text-ink-3">
                        {v.cwe_id ?? "no CWE"}
                        {v.corroborated_count >= 2 && (
                          <span className="ml-2 rounded-full bg-brand-wash px-1.5 text-brand">
                            confirmed by {v.corroborated_count} engines
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="py-2.5 uppercase text-ink-3">{v.engine_category}</td>
                    <td className="py-2.5 text-ink-3">{STATUS_LABEL[v.status]}</td>
                    <td className="py-2.5 text-right tabular-nums">
                      {v.severity_score?.toFixed(1) ?? "—"}
                    </td>
                    <td className="py-2.5 text-right text-ink-3">{relTime(v.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            <Pager
              page={vulns.data.pagination.page}
              total={vulns.data.pagination.total_pages}
              count={vulns.data.pagination.total}
              onPage={(p) => {
                const next = new URLSearchParams(params);
                next.set("page", String(p));
                setParams(next);
              }}
            />
          </>
        )}
      </Card>
    </div>
  );
}
