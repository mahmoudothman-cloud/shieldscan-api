import { useState } from "react";
import { Link } from "react-router";

import { Alert, Button, Card, Field, Input, Select, Spinner } from "@/components/ui";
import { ApiError } from "@/lib/api";
import { FEATURE_LABELS, LIMIT_LABELS, formatLimit, planName } from "@/lib/plan";
import {
  useAdminOrg,
  useAdminOrgs,
  useAdminPlans,
  useAssignSubscription,
  useRemoveOverride,
  useSetOverride,
} from "@/lib/queries";
import type { AdminOrgDetail } from "@/lib/types";

/** Platform admin → Organizations: find an org, see its plan, usage and
 *  overrides; assign a manual subscription; set or remove an override. */
export default function AdminOrgs() {
  const [q, setQ] = useState("");
  const [selected, setSelected] = useState<string | null>(null);
  const orgs = useAdminOrgs(q);
  const detail = useAdminOrg(selected);

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-baseline justify-between">
        <h1 className="font-display text-2xl font-semibold text-ink">Organizations</h1>
        <Link to="/admin/plans" className="text-sm text-brand underline">
          Plans →
        </Link>
      </div>
      <Card title="Find">
        <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Name or slug" />
        {orgs.isPending && <Spinner label="Searching" />}
        {orgs.isError && (
          <Alert tone="error">Couldn't list organizations (platform admin only).</Alert>
        )}
        {orgs.data && (
          <table className="mt-3 w-full text-sm">
            <thead className="text-left text-xs text-ink-3">
              <tr>
                <th className="py-1 pr-3 font-medium">Organization</th>
                <th className="py-1 pr-3 font-medium">Plan</th>
                <th className="py-1 pr-3 font-medium">Status</th>
                <th className="py-1 pr-3 font-medium">Members</th>
                <th className="py-1 pr-3 font-medium">Created</th>
              </tr>
            </thead>
            <tbody>
              {orgs.data.orgs.map((o) => (
                <tr
                  key={o.id}
                  className="cursor-pointer border-t border-line hover:bg-brand-wash/50"
                  onClick={() => setSelected(o.id)}
                >
                  <td className="py-1.5 pr-3">
                    <span className="font-medium text-ink">{o.name}</span>{" "}
                    <span className="text-xs text-ink-3">{o.slug}</span>
                  </td>
                  <td className="py-1.5 pr-3">{planName(o.plan_code)}</td>
                  <td className="py-1.5 pr-3">
                    {o.subscription_status}
                    {o.provider && <span className="text-xs text-ink-3"> · {o.provider}</span>}
                  </td>
                  <td className="py-1.5 pr-3 tabular-nums">{o.members}</td>
                  <td className="py-1.5 pr-3">{new Date(o.created_at).toLocaleDateString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
      {selected && detail.data && <OrgPanel detail={detail.data} />}
      {selected && detail.isPending && <Spinner label="Loading organization" />}
    </div>
  );
}

function OrgPanel({ detail }: { detail: AdminOrgDetail }) {
  const orgId = detail.org.id;
  const plans = useAdminPlans();
  const assign = useAssignSubscription(orgId);
  const setOverride = useSetOverride(orgId);
  const removeOverride = useRemoveOverride(orgId);
  const [planCode, setPlanCode] = useState(detail.org.plan_code);
  const [interval, setInterval] = useState<"month" | "year">("month");
  const [note, setNote] = useState("");
  const [ovKey, setOvKey] = useState("projects.max");
  const [ovValue, setOvValue] = useState("");
  const [ovReason, setOvReason] = useState("");

  const limitKeys = plans.data?.limit_keys ?? [];
  const featureKeys = plans.data?.feature_keys ?? [];
  const errText = (e: unknown) =>
    e instanceof ApiError ? JSON.stringify(e.detail) : e instanceof Error ? e.message : null;

  const submitOverride = () => {
    let value: unknown;
    if (limitKeys.includes(ovKey)) value = Number(ovValue);
    else if (ovKey === "compliance.frameworks")
      value = ovValue
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
    else value = ovValue === "true";
    setOverride.mutate({ key: ovKey, value, ...(ovReason ? { reason: ovReason } : {}) });
  };

  return (
    <Card
      title={`${detail.org.name} — ${planName(detail.org.plan_code)} (${detail.org.subscription_status})`}
      action={
        <span className="text-xs text-ink-3">
          period {detail.period_start}
          {detail.period_end && ` → ${detail.period_end}`}
        </span>
      }
    >
      <div className="grid gap-6 lg:grid-cols-2">
        <section>
          <h3 className="text-sm font-medium text-ink">Effective limits</h3>
          <dl className="mt-2 grid grid-cols-2 gap-x-4 gap-y-0.5 text-xs">
            {Object.entries(detail.effective_limits).map(([k, v]) => (
              <Row
                key={k}
                k={LIMIT_LABELS[k] ?? k}
                v={`${detail.usage[k] !== undefined ? `${detail.usage[k]} / ` : ""}${formatLimit(v)}`}
              />
            ))}
            {Object.entries(detail.effective_features).map(([k, v]) => (
              <Row
                key={k}
                k={FEATURE_LABELS[k] ?? k}
                v={Array.isArray(v) ? v.join(", ") || "—" : v ? "yes" : "no"}
              />
            ))}
          </dl>
          <h3 className="mt-4 text-sm font-medium text-ink">Overrides</h3>
          {detail.overrides.length === 0 && <p className="text-xs text-ink-3">None.</p>}
          <ul className="text-xs">
            {detail.overrides.map((o) => (
              <li
                key={o.key}
                className="flex items-center justify-between border-t border-line py-1"
              >
                <span>
                  <span className="font-medium text-ink">{o.key}</span> = {JSON.stringify(o.value)}
                  {o.reason && <span className="text-ink-3"> · {o.reason}</span>}
                  {o.expires_at && (
                    <span className="text-ink-3">
                      {" "}
                      · until {new Date(o.expires_at).toLocaleDateString()}
                    </span>
                  )}
                </span>
                <Button variant="secondary" size="sm" onClick={() => removeOverride.mutate(o.key)}>
                  Remove
                </Button>
              </li>
            ))}
          </ul>
        </section>

        <section className="flex flex-col gap-4">
          <div>
            <h3 className="text-sm font-medium text-ink">Assign plan (manual subscription)</h3>
            <div className="mt-2 grid gap-2 sm:grid-cols-3">
              <Select value={planCode} onChange={(e) => setPlanCode(e.target.value)}>
                {(plans.data?.plans ?? []).map((p) => (
                  <option key={p.code} value={p.code} disabled={p.live_versions.length === 0}>
                    {p.name}
                  </option>
                ))}
              </Select>
              <Select
                value={interval}
                onChange={(e) => setInterval(e.target.value as "month" | "year")}
              >
                <option value="month">monthly</option>
                <option value="year">annual</option>
              </Select>
              <Input
                value={note}
                onChange={(e) => setNote(e.target.value)}
                placeholder="Note (why)"
              />
            </div>
            <Button
              className="mt-2"
              size="sm"
              disabled={assign.isPending}
              onClick={() =>
                assign.mutate({
                  plan_code: planCode,
                  billing_interval: interval,
                  ...(note ? { note } : {}),
                })
              }
            >
              Assign
            </Button>
            {assign.isSuccess && <Alert tone="success">Subscription assigned.</Alert>}
            {assign.isError && <Alert tone="error">{errText(assign.error)}</Alert>}
          </div>
          <div>
            <h3 className="text-sm font-medium text-ink">Set override</h3>
            <div className="mt-2 grid gap-2 sm:grid-cols-3">
              <Select value={ovKey} onChange={(e) => setOvKey(e.target.value)}>
                {limitKeys.map((k) => (
                  <option key={k} value={k}>
                    {LIMIT_LABELS[k] ?? k}
                  </option>
                ))}
                {featureKeys.map((k) => (
                  <option key={k} value={k}>
                    {FEATURE_LABELS[k] ?? k}
                  </option>
                ))}
              </Select>
              <Field
                label="Value"
                hint={
                  limitKeys.includes(ovKey)
                    ? "number, -1 = unlimited"
                    : ovKey === "compliance.frameworks"
                      ? "slugs, comma-separated"
                      : "true / false"
                }
              >
                {(id) => (
                  <Input id={id} value={ovValue} onChange={(e) => setOvValue(e.target.value)} />
                )}
              </Field>
              <Input
                value={ovReason}
                onChange={(e) => setOvReason(e.target.value)}
                placeholder="Reason"
              />
            </div>
            <Button
              className="mt-2"
              size="sm"
              disabled={setOverride.isPending}
              onClick={submitOverride}
            >
              Save override
            </Button>
            {setOverride.isError && <Alert tone="error">{errText(setOverride.error)}</Alert>}
          </div>
        </section>
      </div>
    </Card>
  );
}

function Row({ k, v }: { k: string; v: string }) {
  return (
    <>
      <dt className="text-ink-3">{k}</dt>
      <dd className="tabular-nums">{v}</dd>
    </>
  );
}
