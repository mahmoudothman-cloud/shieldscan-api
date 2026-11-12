"""Subscription state machine (M12 slice 4; Plans & Billing Review v1.1 §5).

States (``SubscriptionStatus``): PENDING → ACTIVE on the first successful
payment; ACTIVE → PAST_DUE on a failed renewal; PAST_DUE → ACTIVE on a
later success, or → SUSPENDED when the grace window
(``BILLING_GRACE_DAYS``) runs out; SUSPENDED → ACTIVE on resume;
anything → CANCELED. Limits follow: ACTIVE and PAST_DUE are entitled,
SUSPENDED and CANCELED resolve to Free (``services.plans``). Nothing is
ever deleted.

Every processor webhook is written to ``billing_events`` first (unique
on provider + event id) and only then applied, so a redelivery is
acknowledged and skipped. The nightly ``reconcile`` re-reads every
processor-backed subscription from the processor — webhooks are the
fast path, polling is the safety net.
"""

from __future__ import annotations

import logging
from datetime import date, datetime, timedelta, timezone
from typing import Any
from uuid import UUID

import redis.asyncio as redis_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.db.tenant_context import set_tenant_context
from app.models.billing import BillingEvent as BillingEventRow
from app.models.billing import (
    BillingInterval,
    BillingProviderName,
    Invoice,
    InvoiceStatus,
    OrgSubscription,
    Plan,
    PlanVersion,
    SubscriptionStatus,
)
from app.models.identity import Organization, User
from app.services.billing import BillingEvent, BillingProvider, Checkout
from app.services.plans import current_subscription, invalidate_limits, live_version

logger = logging.getLogger(__name__)


class BillingError(Exception):
    def __init__(self, status: int, detail: str) -> None:
        super().__init__(detail)
        self.status = status
        self.detail = detail


def _add_interval(d: date, interval: BillingInterval) -> date:
    if interval == BillingInterval.YEAR:
        return d.replace(year=d.year + 1)
    month = d.month + 1
    year = d.year + (1 if month == 13 else 0)
    month = 1 if month == 13 else month
    try:
        return d.replace(year=year, month=month)
    except ValueError:
        return d.replace(year=year, month=month, day=28)


def _sub_interval(d: date, interval: BillingInterval) -> date:
    if interval == BillingInterval.YEAR:
        return d.replace(year=d.year - 1)
    month = d.month - 1
    year = d.year - (1 if month == 0 else 0)
    month = 12 if month == 0 else month
    try:
        return d.replace(year=year, month=month)
    except ValueError:
        return d.replace(year=year, month=month, day=28)


def vat_part(gross_cents: int) -> int:
    """VAT inside a gross amount at BILLING_VAT_RATE_PERCENT."""
    rate = settings.BILLING_VAT_RATE_PERCENT
    return round(gross_cents - gross_cents * 100 / (100 + rate))


# ------------------------------------------------------------------ provider plans


async def ensure_provider_plan(
    provider: BillingProvider, db: AsyncSession, version: PlanVersion
) -> str:
    """The processor-side plan for a live version, created on first use.
    Stored on the version row; a price change is a new version and so a
    new processor plan — never an in-place amount update for subscribers."""
    if provider.name == BillingProviderName.PAYMOB:
        if version.paymob_plan_id:
            return version.paymob_plan_id
        plan = await db.get(Plan, version.plan_id)
        assert plan is not None
        ref = await provider.create_plan(
            code=plan.code,
            name=plan.name,
            interval=version.billing_interval,
            amount_cents=version.price_egp_cents,
            webhook_url=settings.PAYMOB_WEBHOOK_URL,
        )
        version.paymob_plan_id = ref.provider_plan_id
        await db.flush()
        return ref.provider_plan_id
    return f"manual:{version.id}"


# ------------------------------------------------------------------ checkout


async def start_checkout(
    db: AsyncSession,
    redis: redis_asyncio.Redis | None,
    provider: BillingProvider,
    *,
    org: Organization,
    user: User,
    plan_code: str,
    interval: BillingInterval,
    return_url: str,
    notification_url: str,
) -> tuple[OrgSubscription, Checkout]:
    """Create a PENDING subscription and a processor checkout for it. The
    PENDING row carries no entitlement; ``current_subscription`` keeps
    returning the org's existing (Free/other) row until activation."""
    if plan_code == "free":
        raise BillingError(422, "free_needs_no_checkout")
    version = await live_version(db, plan_code, interval)
    if version is None or version.price_egp_cents <= 0:
        raise BillingError(404, "no_live_version_for_plan_and_interval")
    current = await current_subscription(db, org.id)
    if (
        current is not None
        and current.provider != BillingProviderName.MANUAL
        and current.status in (SubscriptionStatus.ACTIVE, SubscriptionStatus.PAST_DUE)
    ):
        raise BillingError(409, "subscription_already_active")
    # A stale PENDING from an abandoned checkout is replaced.
    stale = (
        await db.execute(
            select(OrgSubscription).where(
                OrgSubscription.organization_id == org.id,
                OrgSubscription.status == SubscriptionStatus.PENDING,
            )
        )
    ).scalars()
    for row in stale:
        row.status = SubscriptionStatus.CANCELED
        row.canceled_at = datetime.now(timezone.utc)
    await db.flush()

    provider_plan_id = await ensure_provider_plan(provider, db, version)
    pending = OrgSubscription(
        organization_id=org.id,
        plan_version_id=version.id,
        status=SubscriptionStatus.PENDING,
        provider=provider.name,
        provider_customer_id=user.email,
        current_period_start=datetime.now(timezone.utc).date(),
        current_period_end=None,
        note=f"checkout started by {user.email}",
    )
    db.add(pending)
    await db.flush()
    checkout = await provider.start_checkout(
        provider_plan_id=provider_plan_id,
        amount_cents=version.price_egp_cents,
        reference=pending.id,
        customer_email=user.email,
        customer_name=user.full_name,
        return_url=return_url,
        notification_url=notification_url,
    )
    return pending, checkout


# ------------------------------------------------------------------ webhook application


async def record_event(db: AsyncSession, event: BillingEvent) -> BillingEventRow | None:
    """Insert the idempotency row; None when the event was seen before."""
    existing = (
        await db.execute(
            select(BillingEventRow).where(
                BillingEventRow.provider == event.provider,
                BillingEventRow.event_id == event.event_id,
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        return None
    row = BillingEventRow(
        provider=event.provider,
        event_id=event.event_id,
        event_type=event.kind,
        payload=event.raw,
        outcome="received",
    )
    db.add(row)
    await db.flush()
    return row


async def _find_subscription(db: AsyncSession, event: BillingEvent) -> OrgSubscription | None:
    """Match by our reference (first payment) or by the processor's
    subscription id (renewals). ``org_subscriptions`` is RLS-scoped and
    the org is not known yet, so this walks organizations — webhooks are
    rare and the match is indexed; a materialised (provider, id) → org
    lookup table is the upgrade if volume ever warrants it."""
    org_ids = list((await db.execute(select(Organization.id))).scalars())
    ref_uuid: UUID | None = None
    if event.reference:
        try:
            ref_uuid = UUID(event.reference)
        except ValueError:
            ref_uuid = None
    for org_id in org_ids:
        await set_tenant_context(db, org_id)
        if ref_uuid is not None:
            row = await db.get(OrgSubscription, ref_uuid)
            if row is not None and row.organization_id == org_id:
                return row
        if event.provider_subscription_id:
            row = (
                await db.execute(
                    select(OrgSubscription).where(
                        OrgSubscription.organization_id == org_id,
                        OrgSubscription.provider == event.provider,
                        OrgSubscription.provider_subscription_id == event.provider_subscription_id,
                        OrgSubscription.status != SubscriptionStatus.CANCELED,
                    )
                )
            ).scalar_one_or_none()
            if row is not None:
                return row
    return None


async def _invoice(
    db: AsyncSession, sub: OrgSubscription, event: BillingEvent, status: InvoiceStatus
) -> None:
    if not event.provider_transaction_id:
        return
    existing = (
        await db.execute(
            select(Invoice.id).where(
                Invoice.provider == event.provider,
                Invoice.provider_transaction_id == event.provider_transaction_id,
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        return
    amount = event.amount_cents or 0
    db.add(
        Invoice(
            organization_id=sub.organization_id,
            subscription_id=sub.id,
            provider=event.provider,
            provider_transaction_id=event.provider_transaction_id,
            status=status,
            amount_cents=amount,
            currency=(event.currency or "EGP")[:3],
            vat_cents=vat_part(amount) if status == InvoiceStatus.PAID else 0,
            period_start=sub.current_period_start,
            period_end=sub.current_period_end,
            paid_at=event.occurred_at if status == InvoiceStatus.PAID else None,
            failure_reason=event.failure_reason,
        )
    )
    await db.flush()


async def apply_event(
    db: AsyncSession, redis: redis_asyncio.Redis | None, event: BillingEvent, row: BillingEventRow
) -> str:
    """Apply one new processor event. Returns the outcome string that is
    also written on the ledger row. Flushes; the caller commits."""
    now = datetime.now(timezone.utc)
    sub = await _find_subscription(db, event)
    if sub is None:
        outcome = "ignored_unmatched"
    else:
        row.organization_id = sub.organization_id
        row.subscription_id = sub.id
        version = await db.get(PlanVersion, sub.plan_version_id)
        interval = version.billing_interval if version is not None else BillingInterval.MONTH
        if event.kind == "payment_succeeded":
            if event.provider_subscription_id and not sub.provider_subscription_id:
                sub.provider_subscription_id = event.provider_subscription_id
            if sub.status == SubscriptionStatus.PENDING:
                # First payment: activate and replace the org's previous row.
                previous = await current_subscription(db, sub.organization_id)
                if previous is not None and previous.id != sub.id:
                    previous.status = SubscriptionStatus.CANCELED
                    previous.canceled_at = now
                start = (event.occurred_at or now).date()
                sub.current_period_start = start
                sub.current_period_end = _add_interval(start, interval)
                sub.status = SubscriptionStatus.ACTIVE
                outcome = "activated"
            elif sub.status in (
                SubscriptionStatus.ACTIVE,
                SubscriptionStatus.PAST_DUE,
                SubscriptionStatus.SUSPENDED,
            ):
                # Renewal: roll the period from its scheduled end (not from
                # the payment date) so a late retry does not drift it.
                base = sub.current_period_end or (event.occurred_at or now).date()
                if base < (event.occurred_at or now).date() - timedelta(
                    days=settings.BILLING_GRACE_DAYS + 30
                ):
                    base = (event.occurred_at or now).date()
                sub.current_period_start = base
                sub.current_period_end = _add_interval(base, interval)
                sub.status = SubscriptionStatus.ACTIVE
                sub.past_due_since = None
                outcome = "renewed"
            else:
                outcome = "ignored_state"
            await _invoice(db, sub, event, InvoiceStatus.PAID)
        elif event.kind == "payment_failed":
            if sub.status == SubscriptionStatus.PENDING:
                outcome = "checkout_failed"  # stays PENDING; user retries
            elif sub.status == SubscriptionStatus.ACTIVE:
                sub.status = SubscriptionStatus.PAST_DUE
                sub.past_due_since = event.occurred_at or now
                outcome = "past_due"
            else:
                outcome = "ignored_state"
            await _invoice(db, sub, event, InvoiceStatus.FAILED)
        elif event.kind == "refunded":
            await _invoice(db, sub, event, InvoiceStatus.REFUNDED)
            outcome = "refund_recorded"
        else:
            outcome = "ignored_unknown"
        await invalidate_limits(redis, sub.organization_id)
    row.outcome = outcome
    row.processed_at = now
    await db.flush()
    logger.info("billing: event %s/%s → %s", event.provider.value, event.event_id, outcome)
    return outcome


# ------------------------------------------------------------------ cancel / reconcile


async def cancel_subscription(
    db: AsyncSession,
    redis: redis_asyncio.Redis | None,
    provider: BillingProvider,
    *,
    org_id: UUID,
    at_period_end: bool = True,
) -> OrgSubscription:
    sub = await current_subscription(db, org_id)
    if sub is None or sub.provider == BillingProviderName.MANUAL:
        raise BillingError(409, "no_processor_subscription")
    if at_period_end and sub.current_period_end and sub.status == SubscriptionStatus.ACTIVE:
        sub.cancel_at_period_end = True
        await db.flush()
        return sub
    if sub.provider_subscription_id:
        await provider.cancel(sub.provider_subscription_id)
    sub.status = SubscriptionStatus.CANCELED
    sub.canceled_at = datetime.now(timezone.utc)
    await db.flush()
    await invalidate_limits(redis, org_id)
    return sub


async def sweep_org(
    db: AsyncSession,
    redis: redis_asyncio.Redis | None,
    provider: BillingProvider,
    org_id: UUID,
    *,
    today: date | None = None,
) -> dict[str, Any]:
    """One org's nightly pass: grace exhaustion, period-end cancels, and a
    processor read-back for processor-backed rows. Flushes; caller commits."""
    today = today or datetime.now(timezone.utc).date()
    now = datetime.now(timezone.utc)
    await set_tenant_context(db, org_id)
    sub = await current_subscription(db, org_id)
    out: dict[str, Any] = {"org": str(org_id), "action": "none"}
    if sub is None or sub.provider == BillingProviderName.MANUAL:
        return out

    if sub.status == SubscriptionStatus.PAST_DUE and sub.past_due_since is not None:
        if now - sub.past_due_since > timedelta(days=settings.BILLING_GRACE_DAYS):
            if sub.provider_subscription_id:
                try:
                    await provider.suspend(sub.provider_subscription_id)
                except Exception:  # noqa: BLE001 — the processor side is best-effort here
                    logger.warning(
                        "billing: suspend at processor failed for %s", sub.id, exc_info=True
                    )
            sub.status = SubscriptionStatus.SUSPENDED
            out["action"] = "suspended"
    if (
        sub.cancel_at_period_end
        and sub.current_period_end is not None
        and sub.current_period_end <= today
        and sub.status != SubscriptionStatus.CANCELED
    ):
        if sub.provider_subscription_id:
            try:
                await provider.cancel(sub.provider_subscription_id)
            except Exception:  # noqa: BLE001
                logger.warning("billing: cancel at processor failed for %s", sub.id, exc_info=True)
        sub.status = SubscriptionStatus.CANCELED
        sub.canceled_at = now
        out["action"] = "canceled_at_period_end"
    if sub.provider_subscription_id and sub.status in (
        SubscriptionStatus.ACTIVE,
        SubscriptionStatus.PAST_DUE,
        SubscriptionStatus.SUSPENDED,
    ):
        try:
            remote = await provider.fetch_subscription(sub.provider_subscription_id)
        except Exception:  # noqa: BLE001
            logger.warning("billing: fetch failed for %s", sub.id, exc_info=True)
            remote = None
        if remote is not None:
            out["remote_state"] = remote.state
            if remote.state in ("canceled", "cancelled", "ended"):
                sub.status = SubscriptionStatus.CANCELED
                sub.canceled_at = now
                out["action"] = "canceled_from_processor"
            elif remote.state == "suspended" and sub.status == SubscriptionStatus.ACTIVE:
                sub.status = SubscriptionStatus.SUSPENDED
                out["action"] = "suspended_from_processor"
            elif (
                remote.next_billing
                and sub.current_period_end
                and remote.next_billing > sub.current_period_end
            ):
                # A renewal we never heard about (lost webhook): trust the processor.
                version = await db.get(PlanVersion, sub.plan_version_id)
                interval = (
                    version.billing_interval if version is not None else BillingInterval.MONTH
                )
                # next_billing is the END of the current period; the start
                # is one interval before it.
                sub.current_period_end = remote.next_billing
                sub.current_period_start = _sub_interval(remote.next_billing, interval)
                if sub.status == SubscriptionStatus.PAST_DUE:
                    sub.status = SubscriptionStatus.ACTIVE
                    sub.past_due_since = None
                out["action"] = "period_from_processor"
    await db.flush()
    if out["action"] != "none":
        await invalidate_limits(redis, org_id)
    return out


async def reconcile_all(
    db: AsyncSession, redis: redis_asyncio.Redis | None, provider: BillingProvider
) -> list[dict[str, Any]]:
    org_ids = list((await db.execute(select(Organization.id))).scalars())
    results = []
    for org_id in org_ids:
        results.append(await sweep_org(db, redis, provider, org_id))
    return results
