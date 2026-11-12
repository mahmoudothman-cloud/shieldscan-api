import { useState } from "react";
import { Link } from "react-router";

import { Alert, Button, Card, Field, Input, Spinner } from "@/components/ui";
import { ApiError } from "@/lib/api";
import { cx } from "@/lib/cx";
import { FEATURE_LABELS, LIMIT_LABELS, formatEgp, formatLimit } from "@/lib/plan";
import { useAdminPlans, usePatchPlan, usePublishPlanVersion } from "@/lib/queries";
import type {
  AdminPlan,
  AdminPlanVersion,
  AdminVersionInput,
  AdminVersionPublished,
} from "@/lib/types";

/** Platform admin → Plans: the catalog as it is, and a "publish new version"
 *  editor per (plan, interval) that retires the live version and shows the diff. */
export default function AdminPlans() {
  const plans = useAdminPlans();
  const [editing, setEditing] = useState<{ code: string; interval: "month" | "year" } | null>(null);

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-baseline justify-between">
        <h1 className="font-display text-2xl font-semibold text-ink">Plans</h1>
        <Link to="/admin/orgs" className="text-sm text-brand underline">
          Organizations →
        </Link>
      </div>
      {plans.isPending && <Spinner label="Loading catalog" />}
      {plans.isError && (
        <Alert tone="error">Couldn't load the catalog (platform admin only).</Alert>
      )}
      {plans.data?.plans.map((p) => (
        <PlanCard
          key={p.code}
          plan={p}
          limitKeys={plans.data.limit_keys}
          featureKeys={plans.data.feature_keys}
          editing={editing?.code === p.code ? editing.interval : null}
          onEdit={(interval) => setEditing(interval ? { code: p.code, interval } : null)}
        />
      ))}
    </div>
  );
}

function PlanCard({
  plan,
  limitKeys,
  featureKeys,
  editing,
  onEdit,
}: {
  plan: AdminPlan;
  limitKeys: string[];
  featureKeys: string[];
  editing: "month" | "year" | null;
  onEdit: (interval: "month" | "year" | null) => void;
}) {
  const patch = usePatchPlan(plan.code);
  const month = plan.live_versions.find((v) => v.billing_interval === "month");
  const year = plan.live_versions.find((v) => v.billing_interval === "year");
  return (
    <Card
      title={`${plan.name} (${plan.code})`}
      action={
        <div className="flex items-center gap-2 text-xs text-ink-3">
          <span>{plan.subscriber_count} subscriber(s)</span>
          <span>· {plan.version_count} version(s)</span>
          <span
            className={cx(
              "rounded-full border px-2 py-0.5",
              plan.is_public ? "text-ok" : "text-ink-3",
            )}
          >
            {plan.is_public ? "public" : "hidden"}
          </span>
          {plan.archived_at && <span className="text-critical">archived</span>}
          <Button
            variant="secondary"
            size="sm"
            disabled={patch.isPending}
            onClick={() => patch.mutate({ is_public: !plan.is_public })}
          >
            {plan.is_public ? "Hide" : "Make public"}
          </Button>
        </div>
      }
    >
      <div className="grid gap-4 lg:grid-cols-2">
        <VersionSummary
          label="Monthly"
          version={month}
          onEdit={() => onEdit("month")}
          editing={editing === "month"}
        />
        <VersionSummary
          label="Annual"
          version={year}
          onEdit={() => onEdit("year")}
          editing={editing === "year"}
        />
      </div>
      {editing && (
        <VersionEditor
          code={plan.code}
          interval={editing}
          base={editing === "month" ? month : year}
          limitKeys={limitKeys}
          featureKeys={featureKeys}
          onClose={() => onEdit(null)}
        />
      )}
    </Card>
  );
}

function VersionSummary({
  label,
  version,
  onEdit,
  editing,
}: {
  label: string;
  version: AdminPlanVersion | undefined;
  onEdit: () => void;
  editing: boolean;
}) {
  return (
    <div className="rounded-control border border-line p-3">
      <div className="flex items-baseline justify-between">
        <span className="text-sm font-medium text-ink">
          {label}
          {version && <span className="ml-2 text-xs text-ink-3">v{version.version}</span>}
        </span>
        <Button variant="secondary" size="sm" onClick={onEdit} disabled={editing}>
          {version ? "New version" : "Create"}
        </Button>
      </div>
      {version ? (
        <dl className="mt-2 grid grid-cols-2 gap-x-4 gap-y-0.5 text-xs">
          <dt className="text-ink-3">EGP</dt>
          <dd className="tabular-nums">{formatEgp(version.price_egp_cents)}</dd>
          <dt className="text-ink-3">USD</dt>
          <dd className="tabular-nums">${(version.price_usd_cents / 100).toFixed(0)}</dd>
          {Object.entries(version.limits).map(([k, v]) => (
            <Fragment2 key={k} k={LIMIT_LABELS[k] ?? k} v={formatLimit(v)} />
          ))}
          {Object.entries(version.features).map(([k, v]) => (
            <Fragment2
              key={k}
              k={FEATURE_LABELS[k] ?? k}
              v={Array.isArray(v) ? v.join(", ") || "—" : v ? "yes" : "no"}
            />
          ))}
        </dl>
      ) : (
        <p className="mt-2 text-xs text-ink-3">No live version.</p>
      )}
    </div>
  );
}

function Fragment2({ k, v }: { k: string; v: string }) {
  return (
    <>
      <dt className="text-ink-3">{k}</dt>
      <dd className="tabular-nums">{v}</dd>
    </>
  );
}

function VersionEditor({
  code,
  interval,
  base,
  limitKeys,
  featureKeys,
  onClose,
}: {
  code: string;
  interval: "month" | "year";
  base: AdminPlanVersion | undefined;
  limitKeys: string[];
  featureKeys: string[];
  onClose: () => void;
}) {
  const publish = usePublishPlanVersion(code);
  const [egp, setEgp] = useState(String((base?.price_egp_cents ?? 0) / 100));
  const [usd, setUsd] = useState(String((base?.price_usd_cents ?? 0) / 100));
  const [limits, setLimits] = useState<Record<string, string>>(
    Object.fromEntries(limitKeys.map((k) => [k, String(base?.limits[k] ?? 0)])),
  );
  const [features, setFeatures] = useState<Record<string, boolean | string>>(
    Object.fromEntries(
      featureKeys.map((k) => {
        const v = base?.features[k];
        return [k, Array.isArray(v) ? v.join(",") : Boolean(v)];
      }),
    ),
  );
  const [note, setNote] = useState("");
  const [result, setResult] = useState<AdminVersionPublished | null>(null);

  const submit = () => {
    const input: AdminVersionInput = {
      billing_interval: interval,
      price_egp_cents: Math.round(Number(egp) * 100),
      price_usd_cents: Math.round(Number(usd) * 100),
      limits: Object.fromEntries(limitKeys.map((k) => [k, Number(limits[k])])),
      features: Object.fromEntries(
        featureKeys.map((k) => {
          const v = features[k];
          if (k === "compliance.frameworks")
            return [
              k,
              String(v === true ? "" : v)
                .split(",")
                .map((s) => s.trim())
                .filter(Boolean),
            ];
          return [k, Boolean(v)];
        }),
      ),
      ...(note ? { change_note: note } : {}),
    };
    publish.mutate(input, { onSuccess: setResult });
  };

  const err =
    publish.error instanceof ApiError
      ? JSON.stringify(publish.error.detail)
      : publish.error?.message;

  return (
    <div className="mt-4 rounded-control border border-brand/30 bg-brand-wash/40 p-4">
      <p className="text-sm font-medium text-ink">
        Publish {interval === "month" ? "monthly" : "annual"} version{" "}
        {base ? `v${base.version + 1}` : "v1"} of {code}
      </p>
      <p className="text-xs text-ink-3">
        The live version is retired; current subscribers keep it. Prices are gross (14% VAT inside).
      </p>
      {result ? (
        <div className="mt-3 text-sm">
          <Alert tone="success">Published v{result.version.version}.</Alert>
          <ul className="mt-2 text-xs">
            {result.diff.map((d) => (
              <li key={d.field} className="tabular-nums">
                {d.field}: {String(d.before)} → {String(d.after)}
              </li>
            ))}
            {result.diff.length === 0 && <li className="text-ink-3">No field changed.</li>}
          </ul>
          <Button className="mt-3" variant="secondary" size="sm" onClick={onClose}>
            Close
          </Button>
        </div>
      ) : (
        <>
          <div className="mt-3 grid gap-3 sm:grid-cols-2">
            <Field label="Price (EGP / period)">
              {(id) => (
                <Input
                  id={id}
                  value={egp}
                  onChange={(e) => setEgp(e.target.value)}
                  inputMode="decimal"
                />
              )}
            </Field>
            <Field label="Price (USD / period)">
              {(id) => (
                <Input
                  id={id}
                  value={usd}
                  onChange={(e) => setUsd(e.target.value)}
                  inputMode="decimal"
                />
              )}
            </Field>
          </div>
          <div className="mt-3 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            {limitKeys.map((k) => (
              <Field key={k} label={LIMIT_LABELS[k] ?? k} hint="-1 = unlimited">
                {(id) => (
                  <Input
                    id={id}
                    value={limits[k] ?? ""}
                    onChange={(e) => setLimits({ ...limits, [k]: e.target.value })}
                    inputMode="numeric"
                  />
                )}
              </Field>
            ))}
          </div>
          <div className="mt-3 flex flex-wrap gap-4">
            {featureKeys.map((k) =>
              k === "compliance.frameworks" ? (
                <Field key={k} label="Compliance frameworks (slugs, comma-separated)">
                  {(id) => (
                    <Input
                      id={id}
                      value={typeof features[k] === "string" ? features[k] : ""}
                      onChange={(e) => setFeatures({ ...features, [k]: e.target.value })}
                      placeholder="iso27001, soc2"
                    />
                  )}
                </Field>
              ) : (
                <label key={k} className="flex items-center gap-2 text-sm text-ink">
                  <input
                    type="checkbox"
                    checked={Boolean(features[k])}
                    onChange={(e) => setFeatures({ ...features, [k]: e.target.checked })}
                  />
                  {FEATURE_LABELS[k] ?? k}
                </label>
              ),
            )}
          </div>
          <Field label="Change note">
            {(id) => (
              <Input
                id={id}
                value={note}
                onChange={(e) => setNote(e.target.value)}
                placeholder="Why this version"
              />
            )}
          </Field>
          {err && <Alert tone="error">{err}</Alert>}
          <div className="mt-3 flex gap-2">
            <Button onClick={submit} disabled={publish.isPending}>
              Publish
            </Button>
            <Button variant="secondary" onClick={onClose}>
              Cancel
            </Button>
          </div>
        </>
      )}
    </div>
  );
}
