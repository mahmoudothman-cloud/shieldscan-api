import { useState } from "react";
import { useSearchParams } from "react-router";

import { Alert, Button, Card, Spinner } from "@/components/ui";
import { ApiError } from "@/lib/api";
import { cx } from "@/lib/cx";
import { formatEgp, planName } from "@/lib/plan";
import { useCancelSubscription, usePlans, useStartCheckout, useSubscription } from "@/lib/queries";
import type { SubscriptionView } from "@/lib/types";

/** Settings → Billing: the subscription as the processor sees it, upgrade
 *  buttons (online checkout when a processor is configured), cancel at
 *  period end, and the invoice list. */
export function BillingCard({ orgId, isAdmin }: { orgId: string; isAdmin: boolean }) {
  const sub = useSubscription(orgId);
  const plans = usePlans();
  const [params] = useSearchParams();
  const returned = params.get("return") === "1";

  return (
    <Card title="Billing" id="billing">
      {sub.isPending && <Spinner label="Loading billing" />}
      {sub.isError && <Alert tone="error">Couldn't load billing.</Alert>}
      {sub.data && (
        <>
          {returned && sub.data.pending_checkout && (
            <Alert tone="info">
              Payment received? It takes a few seconds for the confirmation to arrive — this page
              updates on its own.
            </Alert>
          )}
          <Status data={sub.data} orgId={orgId} isAdmin={isAdmin} />
          {plans.data && isAdmin && (
            <Upgrade
              orgId={orgId}
              current={sub.data}
              plans={plans.data.plans}
              vat={plans.data.vat_rate_percent}
            />
          )}
          {sub.data.invoices.length > 0 && <Invoices invoices={sub.data.invoices} />}
        </>
      )}
    </Card>
  );
}

function Status({
  data,
  orgId,
  isAdmin,
}: {
  data: SubscriptionView;
  orgId: string;
  isAdmin: boolean;
}) {
  const cancel = useCancelSubscription(orgId);
  const end = data.current_period_end
    ? new Date(data.current_period_end).toLocaleDateString()
    : null;
  const tone =
    data.status === "past_due"
      ? "text-warn"
      : data.status === "suspended"
        ? "text-critical"
        : "text-ink-3";
  return (
    <div className="flex flex-wrap items-baseline justify-between gap-2">
      <div>
        <span className="text-lg font-semibold text-ink">{data.plan_name}</span>
        <span className={cx("ml-2 text-sm", tone)}>
          {data.status.replace("_", " ")}
          {data.billing_interval === "year" ? " · annual" : " · monthly"}
          {data.provider !== "manual" && ` · ${data.provider}`}
        </span>
        <p className="text-sm text-ink-3">
          {data.status === "past_due" &&
            "The last renewal failed; we'll retry. Update your card before the grace period ends."}
          {data.status === "suspended" &&
            "Suspended after failed renewals — limits are at the Free level until payment succeeds."}
          {data.cancel_at_period_end && end && `Cancels at the end of the period, ${end}.`}
          {!data.cancel_at_period_end && end && data.status === "active" && `Next renewal ${end}.`}
        </p>
      </div>
      {isAdmin &&
        data.provider !== "manual" &&
        data.status === "active" &&
        !data.cancel_at_period_end && (
          <Button
            variant="secondary"
            size="sm"
            disabled={cancel.isPending}
            onClick={() => cancel.mutate()}
          >
            Cancel at period end
          </Button>
        )}
    </div>
  );
}

function Upgrade({
  orgId,
  current,
  plans,
  vat,
}: {
  orgId: string;
  current: SubscriptionView;
  plans: { code: string; prices: { billing_interval: string; price_egp_cents: number }[] }[];
  vat: number;
}) {
  const checkout = useStartCheckout(orgId);
  const [interval, setInterval] = useState<"month" | "year">("month");
  const paid = plans.filter((p) => p.code !== "free");
  const err =
    checkout.error instanceof ApiError
      ? checkout.error.status === 503
        ? "Online checkout isn't switched on yet — contact us and we'll set the plan for you."
        : String(checkout.error.detail)
      : null;
  return (
    <div className="mt-4 border-t border-line pt-4">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-medium text-ink">Change plan</h3>
        <div className="flex gap-1 text-xs">
          {(["month", "year"] as const).map((i) => (
            <button
              key={i}
              type="button"
              onClick={() => setInterval(i)}
              className={cx(
                "rounded-full border px-2 py-0.5",
                interval === i ? "border-brand bg-brand-wash text-brand" : "border-line text-ink-3",
              )}
            >
              {i === "month" ? "Monthly" : "Annual (10 × monthly)"}
            </button>
          ))}
        </div>
      </div>
      <div className="mt-2 grid gap-2 sm:grid-cols-3">
        {paid.map((p) => {
          const price = p.prices.find((x) => x.billing_interval === interval);
          const isCurrent = p.code === current.plan_code && current.billing_interval === interval;
          return (
            <div
              key={p.code}
              className={cx(
                "rounded-control border p-3",
                isCurrent ? "border-brand" : "border-line",
              )}
            >
              <div className="font-medium text-ink">{planName(p.code)}</div>
              <div className="text-sm tabular-nums text-ink-3">
                {price
                  ? `${formatEgp(price.price_egp_cents)} / ${interval === "month" ? "month" : "year"}`
                  : "—"}
              </div>
              <Button
                className="mt-2"
                size="sm"
                disabled={isCurrent || !price || checkout.isPending || !current.online_checkout}
                onClick={() =>
                  checkout.mutate(
                    { plan_code: p.code, billing_interval: interval },
                    { onSuccess: (r) => window.location.assign(r.checkout_url) },
                  )
                }
              >
                {isCurrent ? "Current plan" : "Pay with card"}
              </Button>
            </div>
          );
        })}
      </div>
      <p className="mt-2 text-xs text-ink-3">
        Prices include {vat}% VAT. Card payments are processed by Paymob; your card details never
        reach ShieldScan.
        {!current.online_checkout &&
          " Online checkout is not switched on yet — contact us to change plan."}
      </p>
      {err && <Alert tone="error">{err}</Alert>}
    </div>
  );
}

function Invoices({ invoices }: { invoices: SubscriptionView["invoices"] }) {
  return (
    <div className="mt-4 border-t border-line pt-4">
      <h3 className="text-sm font-medium text-ink">Invoices</h3>
      <table className="mt-2 w-full text-sm">
        <thead className="text-left text-xs text-ink-3">
          <tr>
            <th className="py-1 pr-3 font-medium">Date</th>
            <th className="py-1 pr-3 font-medium">Period</th>
            <th className="py-1 pr-3 font-medium">Amount</th>
            <th className="py-1 pr-3 font-medium">of which VAT</th>
            <th className="py-1 pr-3 font-medium">Status</th>
          </tr>
        </thead>
        <tbody>
          {invoices.map((i) => (
            <tr key={i.id} className="border-t border-line">
              <td className="py-1 pr-3">
                {new Date(i.paid_at ?? i.created_at).toLocaleDateString()}
              </td>
              <td className="py-1 pr-3 text-ink-3">
                {i.period_start ?? "—"}
                {i.period_end && ` → ${i.period_end}`}
              </td>
              <td className="py-1 pr-3 tabular-nums">{formatEgp(i.amount_cents)}</td>
              <td className="py-1 pr-3 tabular-nums text-ink-3">{formatEgp(i.vat_cents)}</td>
              <td className={cx("py-1 pr-3", i.status === "failed" ? "text-critical" : "")}>
                {i.status}
                {i.failure_reason && (
                  <span className="text-xs text-ink-3"> · {i.failure_reason}</span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
