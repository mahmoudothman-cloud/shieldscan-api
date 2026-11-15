/**
 * Settings → Agents (M14; On-Prem Agent Design v1.0 §4, §6 slice 2).
 *
 * An on-prem agent scans targets the internet cannot reach. The admin
 * creates it here and gets a one-time enrolment token — shown once, like
 * an API key — then runs the printed command on the customer machine.
 * The list shows what the API last heard from each agent: status
 * (pending / online / offline / revoked), version, host, which scanners
 * it has, how many projects are bound. Revoke kills the key at once and
 * unbinds its projects.
 */

import { useState } from "react";
import type { FormEvent } from "react";
import { Check, Copy, Server } from "lucide-react";
import { useOrgId } from "@/lib/auth";
import { useAgents, useCreateAgent, useRevokeAgent } from "@/lib/queries";
import { ApiError } from "@/lib/api";
import { planLimitOf } from "@/lib/plan";
import { relTime } from "@/lib/format";
import { cx } from "@/lib/cx";
import type { AgentItem } from "@/lib/types";
import { PlanLimitAlert } from "@/components/PlanLimitAlert";
import { Alert, Button, Card, Field, Input } from "@/components/ui";

export const AGENT_INSTALL_URL = "https://github.com/mahmoudothman-cloud/shieldscan-agent";

/** Display label + tone for the API's status (offline is derived server-side). */
export function agentStatusView(status: string): { label: string; tone: string; live: boolean } {
  switch (status) {
    case "active":
      return { label: "online", tone: "bg-ok-wash text-ok", live: true };
    case "offline":
      return { label: "offline", tone: "bg-high-wash text-high", live: false };
    case "pending":
      return { label: "waiting for enrolment", tone: "bg-brand-wash text-brand", live: false };
    case "revoked":
      return { label: "revoked", tone: "bg-critical-wash text-critical", live: false };
    default:
      return { label: status, tone: "bg-wash text-ink-3", live: false };
  }
}

export function AgentStatusBadge({ status }: { status: string }) {
  const v = agentStatusView(status);
  return (
    <span
      className={cx(
        "inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-xs font-medium",
        v.tone,
      )}
    >
      {v.live && <span className="size-1.5 rounded-full bg-current" aria-hidden />}
      {v.label}
    </span>
  );
}

export function Agents({ isAdmin }: { isAdmin: boolean }) {
  const orgId = useOrgId();
  const list = useAgents(orgId);
  const create = useCreateAgent(orgId);
  const revoke = useRevokeAgent(orgId);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [confirmRevoke, setConfirmRevoke] = useState<string | null>(null);
  const limit = planLimitOf(create.error);
  const fresh = create.data;

  async function onCreate(e: FormEvent) {
    e.preventDefault();
    await create.mutateAsync({ name: name.trim(), description: description.trim() || null });
    setName("");
    setDescription("");
  }

  const agents = (list.data?.agents ?? []).filter((a) => a.status !== "revoked");
  const revoked = (list.data?.agents ?? []).filter((a) => a.status === "revoked");

  return (
    <Card title="On-prem agents" action={<Server className="size-4 text-ink-3" aria-hidden />}>
      <div className="flex flex-col gap-4">
        <p className="text-sm text-ink-3">
          An agent runs inside your network and scans targets the internet cannot reach — an
          intranet, a staging host, a service on a private address. It only ever makes outbound
          HTTPS calls to ShieldScan; nothing is opened inbound.{" "}
          <a
            href={AGENT_INSTALL_URL}
            target="_blank"
            rel="noreferrer"
            className="text-brand underline"
          >
            Install guide
          </a>
        </p>

        {isAdmin && (
          <form
            onSubmit={onCreate}
            className="flex flex-wrap items-end gap-3 rounded-control bg-wash p-3"
            noValidate
          >
            <div className="min-w-48 flex-1">
              <Field label="New agent name">
                {(id) => (
                  <Input
                    id={id}
                    required
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    placeholder="dc1-scanner"
                  />
                )}
              </Field>
            </div>
            <div className="min-w-48 flex-1">
              <Field label="Description (optional)">
                {(id) => (
                  <Input
                    id={id}
                    value={description}
                    onChange={(e) => setDescription(e.target.value)}
                    placeholder="Cairo office, VLAN 20"
                  />
                )}
              </Field>
            </div>
            <Button type="submit" loading={create.isPending} disabled={!name.trim()}>
              Create agent
            </Button>
          </form>
        )}
        {limit && <PlanLimitAlert limit={limit} />}
        {create.isError && !limit && (
          <Alert tone="error">
            {create.error instanceof ApiError && create.error.status === 403
              ? "Only admins signed in with a password can create agents."
              : "Couldn't create the agent."}
          </Alert>
        )}

        {fresh && <EnrolmentPanel created={fresh} />}

        {list.isPending ? (
          <p className="text-sm text-ink-3">Loading agents…</p>
        ) : list.isError ? (
          <Alert tone="error">Couldn't load agents.</Alert>
        ) : agents.length === 0 ? (
          <p className="text-sm text-ink-3">
            No agents yet.{isAdmin ? " Create one above to scan a private target." : ""}
          </p>
        ) : (
          <ul className="divide-y divide-line-2">
            {agents.map((a) => (
              <AgentRow
                key={a.id}
                agent={a}
                isAdmin={isAdmin}
                confirming={confirmRevoke === a.id}
                onConfirm={() => setConfirmRevoke(a.id)}
                onCancel={() => setConfirmRevoke(null)}
                onRevoke={() => void revoke.mutateAsync(a.id).finally(() => setConfirmRevoke(null))}
                revoking={revoke.isPending && confirmRevoke === a.id}
              />
            ))}
          </ul>
        )}
        {revoke.isError && <Alert tone="error">Couldn't revoke the agent.</Alert>}
        {revoked.length > 0 && (
          <p className="text-xs text-ink-3">
            {revoked.length} revoked: {revoked.map((a) => a.name).join(", ")}
          </p>
        )}
      </div>
    </Card>
  );
}

// ---------------------------------------------------------------- one-time token

function EnrolmentPanel({
  created,
}: {
  created: {
    agent: AgentItem;
    enrolment_token: string;
    enrolment_expires_at: string;
    enrol_command: string;
  };
}) {
  const [copied, setCopied] = useState<"token" | "command" | null>(null);
  function copy(what: "token" | "command", text: string) {
    void navigator.clipboard?.writeText(text).then(() => {
      setCopied(what);
      setTimeout(() => setCopied(null), 1500);
    });
  }
  return (
    <div className="rounded-control border border-brand/40 bg-brand-wash p-3 text-sm">
      <p className="font-medium text-ink">
        Enrolment token for <span className="font-mono">{created.agent.name}</span> — shown once,
        valid until {new Date(created.enrolment_expires_at).toLocaleString()}.
      </p>
      <p className="mt-1 text-xs text-ink-3">
        Install the agent on the machine inside your network, then run this command there. The token
        becomes the agent's key on that machine and is never shown again.
      </p>
      <div className="mt-2 flex items-center gap-2">
        <code className="min-w-0 flex-1 break-all rounded bg-paper px-2 py-1 font-mono text-xs text-ink">
          {created.enrol_command}
        </code>
        <button
          type="button"
          aria-label="Copy enrol command"
          className="rounded p-1 text-ink-3 hover:bg-paper hover:text-ink"
          onClick={() => copy("command", created.enrol_command)}
        >
          {copied === "command" ? (
            <Check className="size-4 text-ok" aria-hidden />
          ) : (
            <Copy className="size-4" aria-hidden />
          )}
        </button>
      </div>
      <div className="mt-2 flex items-center gap-2 text-xs text-ink-3">
        <span>Token only:</span>
        <code className="min-w-0 flex-1 break-all font-mono">{created.enrolment_token}</code>
        <button
          type="button"
          aria-label="Copy enrolment token"
          className="rounded p-1 text-ink-3 hover:bg-paper hover:text-ink"
          onClick={() => copy("token", created.enrolment_token)}
        >
          {copied === "token" ? (
            <Check className="size-4 text-ok" aria-hidden />
          ) : (
            <Copy className="size-4" aria-hidden />
          )}
        </button>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------- row

function AgentRow({
  agent: a,
  isAdmin,
  confirming,
  onConfirm,
  onCancel,
  onRevoke,
  revoking,
}: {
  agent: AgentItem;
  isAdmin: boolean;
  confirming: boolean;
  onConfirm: () => void;
  onCancel: () => void;
  onRevoke: () => void;
  revoking: boolean;
}) {
  const tools = Object.entries(a.tools ?? {}).sort(([x], [y]) => x.localeCompare(y));
  const missing = tools.filter(([, t]) => t.status !== "ok").map(([n]) => n);
  return (
    <li className="flex flex-col gap-2 py-3 sm:flex-row sm:items-start sm:gap-4">
      <div className="min-w-0 flex-1">
        <p className="flex flex-wrap items-center gap-2">
          <span className="font-medium text-ink">{a.name}</span>
          <AgentStatusBadge status={a.status} />
          {a.version && <span className="font-mono text-xs text-ink-3">{a.version}</span>}
        </p>
        {a.description && <p className="text-xs text-ink-3">{a.description}</p>}
        <p className="mt-0.5 text-xs text-ink-3">
          {a.hostname ? `${a.hostname}${a.platform ? ` (${a.platform})` : ""} · ` : ""}
          {a.key_prefix ? `${a.key_prefix}… · ` : ""}
          {a.last_seen_at ? `seen ${relTime(a.last_seen_at)}` : "never seen"} · {a.project_count}{" "}
          {a.project_count === 1 ? "project" : "projects"}
        </p>
        {tools.length > 0 && (
          <p className="mt-1.5 flex flex-wrap gap-1" aria-label={`Tools on ${a.name}`}>
            {tools.map(([n, t]) => (
              <span
                key={n}
                title={t.status === "ok" ? (t.version ?? "ok") : (t.error ?? t.status)}
                className={cx(
                  "rounded px-1.5 py-0.5 font-mono text-[11px]",
                  t.status === "ok"
                    ? "bg-ok-wash text-ok"
                    : "bg-critical-wash text-critical line-through",
                )}
              >
                {n}
              </span>
            ))}
          </p>
        )}
        {missing.length > 0 && a.status !== "pending" && (
          <p className="mt-1 text-xs text-high">
            Missing on the agent: {missing.join(", ")} — jobs for{" "}
            {missing.length === 1 ? "it" : "them"} will fail until installed (
            <code className="font-mono">shieldscan-agent doctor</code>).
          </p>
        )}
      </div>
      {isAdmin &&
        (confirming ? (
          <span className="inline-flex items-center gap-2 text-xs">
            <span className="text-ink-3">
              Revoke? Its key stops working and{" "}
              {a.project_count > 0 ? "its projects are unbound" : "nothing else changes"}.
            </span>
            <Button size="sm" variant="secondary" onClick={onCancel}>
              Keep
            </Button>
            <Button size="sm" variant="danger" loading={revoking} onClick={onRevoke}>
              Revoke
            </Button>
          </span>
        ) : (
          <Button size="sm" variant="ghost" onClick={onConfirm}>
            Revoke
          </Button>
        ))}
    </li>
  );
}
