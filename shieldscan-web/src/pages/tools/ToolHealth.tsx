/**
 * /tools — which engines have a live worker right now, and the workers
 * themselves. Read from the worker registry in Redis; refreshes every
 * 30 s. An engine with no worker is why a scan would sit in "queued".
 */

import { useOrgId } from "@/lib/auth";
import { useToolHealth } from "@/lib/queries";
import { relTime } from "@/lib/format";
import { cx } from "@/lib/cx";
import { Alert, Card, Spinner } from "@/components/ui";

const ENGINE_BLURB: Record<string, string> = {
  nuclei: "Template-driven DAST (CVEs, misconfigurations, exposures)",
  zap: "OWASP ZAP active + passive web scanning",
  wapiti: "Web application fuzzing (XSS, SQLi, file inclusion)",
  nikto: "Web server configuration and known-dangerous files",
  sqlmap: "SQL injection confirmation and exploitation depth",
  sslyze: "TLS configuration and certificate analysis",
  nmap: "Port and service discovery",
  corstest: "CORS policy misconfiguration",
  semgrep: "SAST on connected source",
  gitleaks: "Secrets in source history",
  "trivy-fs": "Dependency and IaC vulnerabilities in source",
  "trivy-container": "Container image vulnerabilities",
  checkov: "Infrastructure-as-code policy checks",
  depcheck: "OWASP Dependency-Check (SCA)",
  recon: "Subdomain enumeration and liveness",
  mobsf: "Mobile app static analysis",
};

export default function ToolHealth() {
  const orgId = useOrgId();
  const health = useToolHealth(orgId);
  if (health.isPending) return <Spinner label="Checking workers" />;
  if (health.isError) return <Alert tone="error">Couldn't read tool health.</Alert>;
  const h = health.data;
  const down = h.tools.filter((t) => !t.available);

  return (
    <div className="flex flex-col gap-6">
      <header>
        <h1 className="text-2xl font-semibold text-ink">Tool health</h1>
        <p className="mt-1 text-sm text-ink-3">
          {h.workers.length} {h.workers.length === 1 ? "worker" : "workers"} online ·{" "}
          {h.tools.length - down.length} of {h.tools.length} engines available · checked{" "}
          {relTime(h.checked_at)}
        </p>
      </header>

      {down.length > 0 && (
        <Alert tone="error">
          No worker is advertising {down.map((t) => t.engine).join(", ")}. Scans that need{" "}
          {down.length === 1 ? "it" : "them"} will wait in the queue until one comes back.
        </Alert>
      )}
      {h.workers.length === 0 && (
        <Alert tone="error">
          No workers are registered. Nothing will scan until the worker service is running.
        </Alert>
      )}

      <div className="grid gap-6 lg:grid-cols-3">
        <Card title="Engines" className="lg:col-span-2">
          <ul className="grid gap-2 sm:grid-cols-2">
            {h.tools.map((t) => (
              <li
                key={t.engine}
                className={cx(
                  "flex items-start gap-3 rounded-control border p-3",
                  t.available ? "border-line" : "border-critical/40 bg-critical-wash",
                )}
              >
                <span
                  className={cx(
                    "mt-1.5 size-2 shrink-0 rounded-full",
                    t.available ? "bg-ok-strong" : "bg-critical",
                  )}
                  aria-hidden
                />
                <div className="min-w-0">
                  <p className="font-medium text-ink">
                    {t.engine}{" "}
                    <span className="text-xs font-normal text-ink-3">
                      · {t.live_worker_count} {t.live_worker_count === 1 ? "worker" : "workers"}
                    </span>
                  </p>
                  <p className="text-xs text-ink-3">{ENGINE_BLURB[t.engine] ?? "Scan engine"}</p>
                </div>
              </li>
            ))}
          </ul>
        </Card>
        <Card title="Workers">
          {h.workers.length === 0 ? (
            <p className="text-sm text-ink-3">None online.</p>
          ) : (
            <ul className="flex flex-col gap-3 text-sm">
              {h.workers.map((w, i) => (
                <li
                  key={w.worker_id ?? `${w.hostname ?? "worker"}-${i}`}
                  className="rounded-control border border-line p-3"
                >
                  <p className="font-medium text-ink">{w.hostname ?? "worker"}</p>
                  <p className="font-mono text-xs text-ink-3">{w.worker_id}</p>
                  <p className="mt-1 text-xs text-ink-3">
                    concurrency {w.concurrency ?? "—"} · {w.engines.length} engines · seen{" "}
                    {relTime(w.last_seen)}
                  </p>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>
    </div>
  );
}
