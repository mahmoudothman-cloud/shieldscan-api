import { Alert, Card, Spinner } from "@/components/ui";
import { cx } from "@/lib/cx";
import {
  FEATURE_LABELS,
  LIMIT_LABELS,
  UNLIMITED,
  formatEgp,
  formatLimit,
  planName,
} from "@/lib/plan";
import { useBillingSummary, usePlans } from "@/lib/queries";
import type { BillingSummaryResponse, PlanPublic } from "@/lib/types";

const METERS = [
  "scans.quick.per_period",
  "scans.full.per_period",
  "scans.mobile.per_period",
  "scans.full_spectrum.per_period",
] as const;
const CAPS = ["projects.max", "users.max", "api_keys.max", "recon.subdomains.max"] as const;
const FEATURES = [
  "ai_fix",
  "cross_layer",
  "compliance.frameworks",
  "cli_write",
  "priority_queue",
] as const;

/** Settings → Plan & usage: what the org is entitled to, how much of it is used
 *  this period, and the catalog to compare against. Checkout arrives with Paymob
 *  (M12 slice 4); until then upgrades are arranged by hand. */
export function PlanUsage({ orgId }: { orgId: string }) {
  const billing = useBillingSummary(orgId);
  const plans = usePlans();

  return (
    <Card title="Plan & usage">
      {billing.isPending && <Spinner label="Loading plan" />}
      {billing.isError && <Alert tone="error">Couldn't load the plan summary.</Alert>}
      {billing.data && <Summary data={billing.data} />}
      {plans.data && billing.data && (
        <Catalog
          plans={plans.data.plans}
          current={billing.data.plan_code}
          vat={plans.data.vat_rate_percent}
        />
      )}
    </Card>
  );
}

function Summary({ data }: { data: BillingSummaryResponse }) {
  const periodEnd = data.period_end ? new Date(data.period_end).toLocaleDateString() : null;
  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
        <span className="text-lg font-semibold text-ink">{data.plan_name}</span>
        <span className="text-sm text-ink-3">
          {data.subscription_status}
          {data.billing_interval === "year" ? " · annual" : " · monthly"}
          {periodEnd && ` · period resets ${periodEnd}`}
        </span>
        {data.overrides.length > 0 && (
          <span className="text-xs text-ink-3">custom limits: {data.overrides.join(", ")}</span>
        )}
      </div>

      <ul className="grid gap-3 sm:grid-cols-2" aria-label="Usage this period">
        {METERS.map((key) => (
          <Meter
            key={key}
            label={LIMIT_LABELS[key] ?? key}
            used={data.usage[key] ?? 0}
            cap={data.limits[key] ?? 0}
          />
        ))}
      </ul>

      <dl className="grid grid-cols-2 gap-x-6 gap-y-1 text-sm sm:grid-cols-4">
        {CAPS.map((key) => (
          <div key={key}>
            <dt className="text-ink-3">{LIMIT_LABELS[key] ?? key}</dt>
            <dd className="font-medium text-ink">{formatLimit(data.limits[key] ?? 0)}</dd>
          </div>
        ))}
      </dl>

      <ul className="flex flex-wrap gap-2 text-xs" aria-label="Features">
        {FEATURES.map((key) => {
          const v = data.features[key];
          const on = Array.isArray(v) ? v.length > 0 : Boolean(v);
          const label =
            Array.isArray(v) && v.length
              ? `${FEATURE_LABELS[key] ?? key}: ${v.join(", ")}`
              : (FEATURE_LABELS[key] ?? key);
          return (
            <li
              key={key}
              className={cx(
                "rounded-full border px-2 py-0.5",
                on ? "border-ok/30 bg-ok-wash text-ok" : "border-line text-ink-3 line-through",
              )}
            >
              {label}
            </li>
          );
        })}
      </ul>
    </div>
  );
}

function Meter({ label, used, cap }: { label: string; used: number; cap: number }) {
  const unlimited = cap === UNLIMITED;
  const pct = unlimited || cap === 0 ? 0 : Math.min(100, Math.round((used / cap) * 100));
  const full = !unlimited && cap > 0 && used >= cap;
  return (
    <li className="flex flex-col gap-1">
      <div className="flex justify-between text-sm">
        <span className="text-ink">{label}</span>
        <span className={cx("tabular-nums", full ? "text-critical" : "text-ink-3")}>
          {used} / {formatLimit(cap)}
        </span>
      </div>
      <div className="h-1.5 w-full overflow-hidden rounded-full bg-line" aria-hidden>
        <div
          className={cx("h-full rounded-full", full ? "bg-critical" : "bg-brand")}
          style={{ width: `${unlimited ? 0 : pct}%` }}
        />
      </div>
    </li>
  );
}

function Catalog({ plans, current, vat }: { plans: PlanPublic[]; current: string; vat: number }) {
  return (
    <div className="mt-6 flex flex-col gap-2">
      <h3 className="text-sm font-medium text-ink">Plans</h3>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead className="text-left text-xs text-ink-3">
            <tr>
              <th className="py-1 pr-3 font-medium">Plan</th>
              <th className="py-1 pr-3 font-medium">Monthly</th>
              <th className="py-1 pr-3 font-medium">Annual</th>
              <th className="py-1 pr-3 font-medium">Projects</th>
              <th className="py-1 pr-3 font-medium">Full scans</th>
              <th className="py-1 pr-3 font-medium">Members</th>
            </tr>
          </thead>
          <tbody>
            {plans.map((p) => {
              const month = p.prices.find((x) => x.billing_interval === "month");
              const year = p.prices.find((x) => x.billing_interval === "year");
              const isCurrent = p.code === current;
              return (
                <tr
                  key={p.code}
                  className={cx("border-t border-line", isCurrent && "bg-brand-wash")}
                >
                  <td className="py-1.5 pr-3 font-medium text-ink">
                    {planName(p.code)}
                    {isCurrent && <span className="ml-2 text-xs text-brand">current</span>}
                  </td>
                  <td className="py-1.5 pr-3 tabular-nums">
                    {month ? formatEgp(month.price_egp_cents) : "—"}
                  </td>
                  <td className="py-1.5 pr-3 tabular-nums">
                    {year ? formatEgp(year.price_egp_cents) : "—"}
                  </td>
                  <td className="py-1.5 pr-3 tabular-nums">
                    {month ? formatLimit(month.limits["projects.max"] ?? 0) : "—"}
                  </td>
                  <td className="py-1.5 pr-3 tabular-nums">
                    {month ? formatLimit(month.limits["scans.full.per_period"] ?? 0) : "—"}
                  </td>
                  <td className="py-1.5 pr-3 tabular-nums">
                    {month ? formatLimit(month.limits["users.max"] ?? 0) : "—"}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      <p className="text-xs text-ink-3">
        Prices include {vat}% VAT. Change plan from the Billing card above.
      </p>
    </div>
  );
}
