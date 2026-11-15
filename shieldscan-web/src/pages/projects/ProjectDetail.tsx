/**
 * /projects/:projectId — target facts, ownership verification (DNS TXT
 * or meta tag, with the exact record to add), run-a-scan panel, and the
 * project's scan history. Flow F2 of the approved design starts here.
 */

import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router";
import { Check, Copy, Server, ShieldCheck } from "lucide-react";
import { useOrgId } from "@/lib/auth";
import {
  useAgents,
  useArchiveProject,
  useCreateScan,
  useOrg,
  useProject,
  useProjectScans,
  useUpdateProject,
  useVerifyDomain,
} from "@/lib/queries";
import { AgentStatusBadge } from "@/pages/settings/Agents";
import { PlanLimitAlert } from "@/components/PlanLimitAlert";
import { ApiError } from "@/lib/api";
import { planLimitOf } from "@/lib/plan";
import type { ProjectResponse, ScanCreateInput, VerifyDomainFailure } from "@/lib/types";
import { duration, relTime, scanTypeLabel } from "@/lib/format";
import { Alert, Button, Card, Empty, Field, Select, Spinner, StatusBadge } from "@/components/ui";

export default function ProjectDetail() {
  const { projectId = "" } = useParams();
  const orgId = useOrgId();
  const project = useProject(orgId, projectId);

  if (project.isPending) return <Spinner label="Loading project" />;
  if (project.isError)
    return <Alert tone="error">This project doesn't exist or you don't have access to it.</Alert>;
  const p = project.data;

  return (
    <div className="flex flex-col gap-6">
      <header className="flex items-start justify-between gap-4">
        <div>
          <Link to="/projects" className="text-sm text-brand">
            ← Projects
          </Link>
          <h1 className="mt-1 text-2xl font-semibold text-ink">{p.name}</h1>
          <p className="mt-1 text-sm text-ink-3">
            <a href={p.target_url} target="_blank" rel="noreferrer" className="hover:text-brand">
              {p.target_url}
            </a>
            {" · "}
            {p.domain_verified ? (
              <span className="inline-flex items-center gap-1 text-ok">
                <ShieldCheck className="size-4" aria-hidden /> verified
              </span>
            ) : p.agent_id ? (
              <span className="inline-flex items-center gap-1 text-ok">
                <Server className="size-4" aria-hidden /> verified by agent enrolment
              </span>
            ) : (
              <span className="text-high">not verified</span>
            )}
          </p>
        </div>
        <ArchiveButton orgId={orgId} project={p} />
      </header>

      <div className="grid gap-6 lg:grid-cols-3">
        <div className="flex flex-col gap-6 lg:col-span-2">
          {!p.domain_verified && !p.agent_id && <VerifyPanel orgId={orgId} project={p} />}
          <ScanHistory orgId={orgId} projectId={p.id} />
        </div>
        <div className="flex flex-col gap-6">
          <RunScanPanel orgId={orgId} project={p} />
          <AgentPanel orgId={orgId} project={p} />
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------- verification

function VerifyPanel({ orgId, project }: { orgId: string; project: ProjectResponse }) {
  const verify = useVerifyDomain(orgId, project.id);
  const [method, setMethod] = useState<"dns_txt" | "meta_tag">("dns_txt");
  const txtHost = `_shieldscan-verify.${project.root_domain}`;
  const metaTag = `<meta name="shieldscan-verification" content="${project.verification_token}">`;
  const failure =
    verify.error instanceof ApiError && verify.error.status === 400
      ? (verify.error.detail as VerifyDomainFailure)
      : null;

  return (
    <Card title="Verify ownership" className="border-warn/50">
      <div id="verify" className="flex flex-col gap-4 text-sm">
        <p className="text-ink-3">
          Full scans send real attack payloads, so we need proof this target is yours. Quick scans
          (read-only) work without it.
        </p>
        <div className="flex gap-2">
          <Button
            size="sm"
            variant={method === "dns_txt" ? "primary" : "secondary"}
            onClick={() => setMethod("dns_txt")}
          >
            DNS TXT record
          </Button>
          <Button
            size="sm"
            variant={method === "meta_tag" ? "primary" : "secondary"}
            onClick={() => setMethod("meta_tag")}
          >
            HTML meta tag
          </Button>
        </div>
        {method === "dns_txt" ? (
          <div className="grid gap-2 rounded-control bg-wash p-3 font-mono text-xs">
            <Row label="Type" value="TXT" />
            <Row label="Host" value={txtHost} copy />
            <Row label="Value" value={project.verification_token} copy />
            <p className="mt-1 font-sans text-ink-3">
              DNS changes can take a few minutes to propagate. We check the record at every
              verification attempt.
            </p>
          </div>
        ) : (
          <div className="grid gap-2 rounded-control bg-wash p-3 font-mono text-xs">
            <Row label="Add to <head> of" value={project.target_url} />
            <Row label="Tag" value={metaTag} copy />
          </div>
        )}
        {failure && (
          <Alert tone="error">
            Not verified yet: {failure.failure_reason.replaceAll("_", " ")}.
            {failure.expected_record ? (
              <>
                {" "}
                Expected <code className="font-mono">{failure.expected_record}</code>.
              </>
            ) : null}
          </Alert>
        )}
        {verify.isError && !failure && (
          <Alert tone="error">Verification request failed. Try again in a moment.</Alert>
        )}
        <div>
          <Button onClick={() => verify.mutate(method)} loading={verify.isPending}>
            Check now
          </Button>
        </div>
      </div>
    </Card>
  );
}

function Row({ label, value, copy }: { label: string; value: string; copy?: boolean }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="flex items-center gap-3">
      <span className="w-28 shrink-0 font-sans text-ink-3">{label}</span>
      <span className="min-w-0 flex-1 break-all text-ink">{value}</span>
      {copy && (
        <button
          type="button"
          aria-label={`Copy ${label}`}
          className="shrink-0 rounded p-1 text-ink-3 hover:bg-line-2 hover:text-ink"
          onClick={() => {
            void navigator.clipboard?.writeText(value).then(() => {
              setCopied(true);
              setTimeout(() => setCopied(false), 1500);
            });
          }}
        >
          {copied ? (
            <Check className="size-4 text-ok" aria-hidden />
          ) : (
            <Copy className="size-4" aria-hidden />
          )}
        </button>
      )}
    </div>
  );
}

// ---------------------------------------------------------------- run a scan

interface ScanTypeOption {
  value: ScanCreateInput["scan_type"];
  label: string;
  needsVerified: boolean;
  needsRepo?: boolean;
  needsImage?: boolean;
  /** Not runnable on an on-prem agent (source, container, mobile stay in the cloud). */
  notOnAgent?: boolean;
  blurb: string;
}

const QUICK: ScanTypeOption = {
  value: "quick",
  label: "Quick (passive, ~2 min)",
  needsVerified: false,
  blurb: "Headers, TLS, exposed files, technology fingerprints. Read-only.",
};

const SCAN_TYPES: ScanTypeOption[] = [
  QUICK,
  {
    value: "full_web",
    label: "Full web (all DAST engines)",
    needsVerified: true,
    blurb: "Recon, ZAP, Nuclei, Wapiti, Nikto, SQLMap, SSLyze, CORS. Sends real payloads.",
  },
  {
    value: "full_web_source",
    label: "Full web + source",
    needsVerified: true,
    needsRepo: true,
    notOnAgent: true,
    blurb: "Full web plus Semgrep, Gitleaks, Trivy-fs, Checkov on your repository.",
  },
  {
    value: "api",
    label: "API",
    needsVerified: true,
    blurb: "Endpoint discovery and API-focused checks.",
  },
  {
    value: "container",
    label: "Container image",
    needsVerified: false,
    needsImage: true,
    notOnAgent: true,
    blurb: "Trivy scan of the configured image.",
  },
];

function RunScanPanel({ orgId, project }: { orgId: string; project: ProjectResponse }) {
  const navigate = useNavigate();
  const create = useCreateScan(orgId, project.id);
  const onAgent = project.agent_id !== null;
  const [type, setType] = useState<ScanCreateInput["scan_type"]>(
    project.domain_verified || onAgent ? "full_web" : "quick",
  );
  const chosen = SCAN_TYPES.find((t) => t.value === type) ?? QUICK;
  const blocked =
    onAgent && chosen.notOnAgent
      ? "This scan type runs in the cloud only; unbind the agent to use it."
      : chosen.needsVerified && !project.domain_verified && !onAgent
        ? "Verify the domain first."
        : chosen.needsRepo && !project.source_repo_url
          ? "Add a repository URL to the project first."
          : chosen.needsImage && !project.container_image
            ? "Add a container image to the project first."
            : null;

  async function run() {
    const scan = await create.mutateAsync({ scan_type: type });
    void navigate(`/scans/${scan.id}`);
  }

  const limit = planLimitOf(create.error);
  const err =
    limit === null && create.error instanceof ApiError
      ? create.error.detail === "domain_not_verified"
        ? "Verify the domain before running this scan type."
        : isDetailError(create.error.detail, "agent_offline")
          ? "The agent bound to this project is offline — start it (or check `shieldscan-agent doctor` on that machine) and try again."
          : isDetailError(create.error.detail, "scan_type_not_supported_on_agent")
            ? "This scan type cannot run on an on-prem agent."
            : create.error.status === 429
              ? "Too many scans started at once. Try again in a minute."
              : String(create.error.detail ?? "Couldn't start the scan.")
      : null;

  return (
    <Card title="Run a scan">
      <div className="flex flex-col gap-4">
        <Field label="Scan type">
          {(id) => (
            <Select
              id={id}
              value={type}
              onChange={(e) => setType(e.target.value as ScanCreateInput["scan_type"])}
            >
              {SCAN_TYPES.map((t) => (
                <option key={t.value} value={t.value}>
                  {t.label}
                </option>
              ))}
            </Select>
          )}
        </Field>
        <p className="text-sm text-ink-3">{chosen.blurb}</p>
        {onAgent && !blocked && (
          <p className="text-xs text-ink-3">
            Runs on your on-prem agent; engines it does not have installed will fail visibly.
          </p>
        )}
        {blocked && <Alert tone="info">{blocked}</Alert>}
        {limit && <PlanLimitAlert limit={limit} />}
        {err && <Alert tone="error">{err}</Alert>}
        <Button onClick={() => void run()} disabled={blocked !== null} loading={create.isPending}>
          Start {scanTypeLabel(type).toLowerCase()} scan
        </Button>
      </div>
    </Card>
  );
}

function isDetailError(detail: unknown, code: string): boolean {
  return (
    typeof detail === "object" && detail !== null && (detail as { error?: string }).error === code
  );
}

// ---------------------------------------------------------------- on-prem agent (M14)

/**
 * Bind the project to one of the org's agents. A bound project's scans
 * run only on that agent and need no domain verification — the admin's
 * enrolment is the authorisation. Admin-only; members see the state.
 */
function AgentPanel({ orgId, project }: { orgId: string; project: ProjectResponse }) {
  const org = useOrg(orgId);
  const isAdmin = org.data?.my_role === "admin";
  const agents = useAgents(orgId);
  const update = useUpdateProject(orgId, project.id);
  const usable = (agents.data?.agents ?? []).filter((a) => a.status !== "revoked");
  const bound = usable.find((a) => a.id === project.agent_id) ?? null;
  const limit = planLimitOf(update.error);
  const err =
    limit === null && update.error instanceof ApiError
      ? update.error.status === 403
        ? "Only admins can bind an agent."
        : update.error.status === 404
          ? "That agent no longer exists or was revoked."
          : "Couldn't update the binding."
      : null;

  if (agents.isPending || org.isPending) return null;
  // Nothing to show a non-admin on a project with no agents in the org.
  if (!isAdmin && usable.length === 0 && !project.agent_id) return null;

  return (
    <Card title="On-prem agent" action={<Server className="size-4 text-ink-3" aria-hidden />}>
      <div className="flex flex-col gap-3 text-sm">
        {bound ? (
          <p className="text-ink-3">
            Scans run on <span className="font-medium text-ink">{bound.name}</span>{" "}
            <AgentStatusBadge status={bound.status} /> inside your network. Domain verification is
            not needed: the enrolment is the authorisation.
          </p>
        ) : project.agent_id ? (
          <Alert tone="error">
            Bound to an agent that is no longer listed. Rebind or unbind before scanning.
          </Alert>
        ) : (
          <p className="text-ink-3">
            Private target (intranet, staging, a service on a private address)? Bind an agent that
            runs inside that network and scans go through it instead of the cloud.
          </p>
        )}
        {isAdmin && (
          <Field label="Agent">
            {(id) => (
              <Select
                id={id}
                value={project.agent_id ?? ""}
                disabled={update.isPending}
                onChange={(e) => update.mutate({ agent_id: e.target.value || null })}
              >
                <option value="">None — scan from the cloud</option>
                {usable.map((a) => (
                  <option key={a.id} value={a.id}>
                    {a.name} ({agentStatusLabel(a.status)})
                  </option>
                ))}
              </Select>
            )}
          </Field>
        )}
        {isAdmin && usable.length === 0 && (
          <p className="text-xs text-ink-3">
            No agents yet —{" "}
            <Link to="/settings" className="text-brand underline">
              create one in Settings
            </Link>
            .
          </p>
        )}
        {limit && <PlanLimitAlert limit={limit} />}
        {err && <Alert tone="error">{err}</Alert>}
      </div>
    </Card>
  );
}

function agentStatusLabel(status: string): string {
  return status === "active" ? "online" : status === "pending" ? "not enrolled yet" : status;
}

// ---------------------------------------------------------------- history

function ScanHistory({ orgId, projectId }: { orgId: string; projectId: string }) {
  const scans = useProjectScans(orgId, projectId);
  return (
    <Card title="Scans">
      {scans.isPending ? (
        <Spinner />
      ) : !scans.data || scans.data.items.length === 0 ? (
        <Empty title="No scans for this project yet" />
      ) : (
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-xs font-medium uppercase tracking-wide text-ink-3">
              <th className="pb-2">Type</th>
              <th className="pb-2">Status</th>
              <th className="pb-2 text-right">Findings</th>
              <th className="pb-2 text-right">Duration</th>
              <th className="pb-2 text-right">Started</th>
            </tr>
          </thead>
          <tbody>
            {scans.data.items.map((s) => (
              <tr key={s.id} className="border-t border-line-2">
                <td className="py-2.5 font-medium text-ink">
                  <Link to={`/scans/${s.id}`} className="hover:text-brand">
                    {scanTypeLabel(s.scan_type)}
                  </Link>
                </td>
                <td className="py-2.5">
                  <StatusBadge status={s.status} detail={`${s.jobs_terminal}/${s.jobs_total}`} />
                </td>
                <td className="py-2.5 text-right tabular-nums">{s.vulnerability_count}</td>
                <td className="py-2.5 text-right text-ink-3">
                  {s.started_at && s.completed_at
                    ? duration(
                        new Date(s.completed_at).getTime() - new Date(s.started_at).getTime(),
                      )
                    : "—"}
                </td>
                <td className="py-2.5 text-right text-ink-3">{relTime(s.created_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Card>
  );
}

// ---------------------------------------------------------------- archive

function ArchiveButton({ orgId, project }: { orgId: string; project: ProjectResponse }) {
  const navigate = useNavigate();
  const archive = useArchiveProject(orgId);
  const [confirm, setConfirm] = useState(false);
  if (!confirm)
    return (
      <Button variant="ghost" size="sm" onClick={() => setConfirm(true)}>
        Archive
      </Button>
    );
  return (
    <div className="flex items-center gap-2 text-sm">
      <span className="text-ink-3">Archive {project.name}? Scans stay readable.</span>
      <Button size="sm" variant="secondary" onClick={() => setConfirm(false)}>
        Keep
      </Button>
      <Button
        size="sm"
        variant="danger"
        loading={archive.isPending}
        onClick={() => void archive.mutateAsync(project.id).then(() => navigate("/projects"))}
      >
        Archive
      </Button>
    </div>
  );
}
