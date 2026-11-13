/**
 * /compliance — org-wide posture per framework: how many controls pass,
 * fail (an open vulnerability maps to them) or are not assessed by
 * automated scanning at all. The last bucket is shown as plainly as the
 * first two: a scanner can only ever evidence a slice of SOC 2 or ISO.
 */

import { useState } from "react";
import { Link } from "react-router";
import { useOrgId } from "@/lib/auth";
import { useFrameworkCatalog, useOrgPosture } from "@/lib/queries";
import type { ControlState, FrameworkPosture } from "@/lib/types";
import { cx } from "@/lib/cx";
import { Alert, Card, Spinner } from "@/components/ui";

const STATE_LABEL: Record<ControlState, string> = {
  pass: "Passing",
  fail: "Failing",
  not_assessed: "Not assessed by scanning",
};
const STATE_TONE: Record<ControlState, string> = {
  pass: "bg-ok-wash text-ok",
  fail: "bg-critical-wash text-critical",
  not_assessed: "bg-wash-2 text-ink-3",
};

export default function Compliance() {
  const orgId = useOrgId();
  const posture = useOrgPosture(orgId);
  const catalog = useFrameworkCatalog(orgId);
  const [filter, setFilter] = useState<ControlState | "all">("all");

  if (posture.isPending) return <Spinner label="Computing posture" />;
  if (posture.isError) return <Alert tone="error">Couldn't load compliance posture.</Alert>;

  const lockedFrameworks = (catalog.data?.frameworks ?? []).filter((f) => f.in_plan === false);
  const descriptions = new Map<string, string | null>();
  for (const fw of catalog.data?.frameworks ?? [])
    for (const c of fw.controls) descriptions.set(`${fw.slug}:${c.control_id}`, c.description);

  return (
    <div className="flex flex-col gap-6">
      <header>
        <h1 className="text-2xl font-semibold text-ink">Compliance posture</h1>
        <p className="mt-1 text-sm text-ink-3">
          A control fails while any{" "}
          <Link to="/vulnerabilities" className="text-brand">
            open vulnerability
          </Link>{" "}
          maps to it; resolve or triage the finding and it passes again. Controls a scanner cannot
          evidence (policies, training, physical access) are listed as not assessed — your auditor
          still needs those from you.
        </p>
      </header>

      <div className="flex flex-wrap gap-2">
        {(["all", "fail", "pass", "not_assessed"] as const).map((f) => (
          <button
            key={f}
            type="button"
            aria-pressed={filter === f}
            onClick={() => setFilter(f)}
            className={cx(
              "rounded-full border px-3 py-1 text-xs font-medium",
              filter === f
                ? "border-ink bg-ink text-white"
                : "border-line bg-paper text-ink-3 hover:border-ink-3",
            )}
          >
            {f === "all" ? "All controls" : STATE_LABEL[f]}
          </button>
        ))}
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        {posture.data.frameworks.map((fw) => (
          <FrameworkCard key={fw.slug} fw={fw} filter={filter} descriptions={descriptions} />
        ))}
      </div>
      {lockedFrameworks.length > 0 && (
        <p className="text-sm text-ink-3">
          Not in your plan: {lockedFrameworks.map((f) => f.name).join(", ")}.{" "}
          <Link to="/settings/billing" className="text-brand underline">
            See plans
          </Link>
        </p>
      )}
    </div>
  );
}

function FrameworkCard({
  fw,
  filter,
  descriptions,
}: {
  fw: FrameworkPosture;
  filter: ControlState | "all";
  descriptions: Map<string, string | null>;
}) {
  const assessed = fw.summary.pass + fw.summary.fail;
  const pct = assessed ? Math.round((fw.summary.pass / assessed) * 100) : null;
  const rows = fw.controls.filter((c) => filter === "all" || c.state === filter);
  return (
    <Card
      title={`${fw.name} ${fw.version}`}
      action={
        <span className="text-xs text-ink-3">
          {fw.summary.fail} failing · {fw.summary.pass} passing · {fw.summary.not_assessed} not
          assessed
        </span>
      }
    >
      <div className="mb-4">
        <div className="flex items-end justify-between">
          <p className="font-display text-3xl font-semibold text-ink">
            {pct === null ? "—" : `${pct}%`}
          </p>
          <p className="text-xs text-ink-3">
            of scanner-assessable controls passing ({assessed} of {fw.summary.total})
          </p>
        </div>
        <div className="mt-2 flex h-2 overflow-hidden rounded-full bg-wash-2" aria-hidden>
          <div
            className="bg-ok-strong"
            style={{ width: `${(fw.summary.pass / fw.summary.total) * 100}%` }}
          />
          <div
            className="bg-critical"
            style={{ width: `${(fw.summary.fail / fw.summary.total) * 100}%` }}
          />
        </div>
      </div>
      {rows.length === 0 ? (
        <p className="text-sm text-ink-3">No controls in this state.</p>
      ) : (
        <ul className="divide-y divide-line-2">
          {rows.map((c) => (
            <li key={c.control_id} className="flex items-start gap-3 py-2 text-sm">
              <span
                className={cx(
                  "mt-0.5 shrink-0 rounded-full px-2 py-0.5 text-[11px] font-medium",
                  STATE_TONE[c.state],
                )}
              >
                {STATE_LABEL[c.state]}
              </span>
              <div className="min-w-0">
                <p className="text-ink">
                  <span className="font-mono text-xs text-ink-3">{c.control_id}</span> {c.title}
                </p>
                {descriptions.get(`${fw.slug}:${c.control_id}`) && (
                  <p className="mt-0.5 text-xs text-ink-3">
                    {descriptions.get(`${fw.slug}:${c.control_id}`)}
                  </p>
                )}
              </div>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}
