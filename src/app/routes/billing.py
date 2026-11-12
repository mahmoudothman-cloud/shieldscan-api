"""Billing routes (M12 slice 4): checkout, current subscription, cancel,
processor webhook, admin reconcile."""

from __future__ import annotations

import logging
from typing import Any
from uuid import UUID

import redis.asyncio as redis_asyncio
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.dependencies import (
    AuthIdentity,
    get_db,
    require_org_membership,
    require_platform_admin,
)
from app.models.billing import (
    BillingInterval,
    BillingProviderName,
    Invoice,
    OrgSubscription,
    Plan,
    PlanVersion,
    SubscriptionStatus,
)
from app.models.identity import MembershipRole, Organization
from app.redis_client import get_redis
from app.schemas.plans import CheckoutRequest, CheckoutResponse, InvoiceOut, SubscriptionView
from app.services.billing import get_provider, online_checkout_available
from app.services.billing.manual import CheckoutUnavailable
from app.services.billing.subscriptions import (
    BillingError,
    apply_event,
    cancel_subscription,
    reconcile_all,
    record_event,
    start_checkout,
)
from app.services.plans import current_subscription, live_version

logger = logging.getLogger(__name__)
router = APIRouter(tags=["billing"])


def _raise(e: BillingError) -> HTTPException:
    return HTTPException(status_code=e.status, detail=e.detail)


async def require_billing_admin(
    identity: AuthIdentity = Depends(require_org_membership(jwt_only=True)),
) -> AuthIdentity:
    """Org admin with a user session: the only one who may start or cancel
    a paid subscription."""
    if identity.role != MembershipRole.ADMIN:
        raise HTTPException(status_code=403, detail="insufficient_role")
    return identity


@router.get("/orgs/{org_id}/billing/subscription", response_model=SubscriptionView)
async def get_subscription(
    org_id: UUID,
    identity: AuthIdentity = Depends(require_org_membership()),
    db: AsyncSession = Depends(get_db),
) -> SubscriptionView:
    sub = await current_subscription(db, org_id)
    version = (
        await db.get(PlanVersion, sub.plan_version_id)
        if sub is not None
        else await live_version(db, "free")
    )
    assert version is not None
    plan = await db.get(Plan, version.plan_id)
    assert plan is not None
    pending = (
        await db.execute(
            select(OrgSubscription.id).where(
                OrgSubscription.organization_id == org_id,
                OrgSubscription.status == SubscriptionStatus.PENDING,
            )
        )
    ).first() is not None
    invoices = list(
        (
            await db.execute(
                select(Invoice)
                .where(Invoice.organization_id == org_id)
                .order_by(Invoice.created_at.desc())
                .limit(24)
            )
        ).scalars()
    )
    return SubscriptionView(
        plan_code=plan.code,
        plan_name=plan.name,
        billing_interval=version.billing_interval.value,
        status=sub.status.value if sub is not None else "active",
        provider=sub.provider.value if sub is not None else "manual",
        current_period_start=sub.current_period_start
        if sub is not None
        else version.effective_from.date(),
        current_period_end=sub.current_period_end if sub is not None else None,
        cancel_at_period_end=bool(sub.cancel_at_period_end) if sub is not None else False,
        past_due_since=sub.past_due_since if sub is not None else None,
        online_checkout=online_checkout_available(),
        pending_checkout=pending,
        invoices=[InvoiceOut.model_validate(i) for i in invoices],
    )


@router.post("/orgs/{org_id}/billing/checkout", response_model=CheckoutResponse)
async def checkout(
    org_id: UUID,
    body: CheckoutRequest,
    identity: AuthIdentity = Depends(require_billing_admin),
    db: AsyncSession = Depends(get_db),
    redis: redis_asyncio.Redis = Depends(get_redis),
) -> CheckoutResponse:
    assert identity.user is not None
    try:
        interval = BillingInterval(body.billing_interval)
    except ValueError:
        raise HTTPException(status_code=422, detail="invalid_billing_interval")
    org = await db.get(Organization, org_id)
    assert org is not None
    base = settings.APP_BASE_URL.rstrip("/")
    try:
        pending, co = await start_checkout(
            db,
            redis,
            get_provider(),
            org=org,
            user=identity.user,
            plan_code=body.plan_code,
            interval=interval,
            return_url=f"{base}/settings/billing?return=1",
            notification_url=settings.PAYMOB_WEBHOOK_URL or f"{base}/v1/billing/webhooks/paymob",
        )
    except CheckoutUnavailable:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="online_checkout_unavailable"
        )
    except BillingError as e:
        raise _raise(e)
    await db.commit()
    return CheckoutResponse(subscription_id=pending.id, checkout_url=co.url)


@router.post("/orgs/{org_id}/billing/cancel", response_model=SubscriptionView)
async def cancel(
    org_id: UUID,
    identity: AuthIdentity = Depends(require_billing_admin),
    db: AsyncSession = Depends(get_db),
    redis: redis_asyncio.Redis = Depends(get_redis),
) -> SubscriptionView:
    try:
        await cancel_subscription(db, redis, get_provider(), org_id=org_id, at_period_end=True)
    except BillingError as e:
        raise _raise(e)
    await db.commit()
    return await get_subscription(org_id, identity, db)


@router.post("/billing/webhooks/paymob", status_code=status.HTTP_200_OK)
async def paymob_webhook(
    request: Request,
    db: AsyncSession = Depends(get_db),
    redis: redis_asyncio.Redis = Depends(get_redis),
) -> Response:
    """Public, HMAC-gated. Always 200 once the signature checks out so
    Paymob stops retrying; what we did with it is on ``billing_events``."""
    provider = get_provider()
    if provider.name != BillingProviderName.PAYMOB:
        raise HTTPException(status_code=404, detail="not_found")
    try:
        body: Any = await request.json()
    except ValueError:
        raise HTTPException(status_code=400, detail="invalid_json")
    if not isinstance(body, dict) or not provider.verify_webhook(body, dict(request.query_params)):
        raise HTTPException(status_code=401, detail="bad_signature")
    event = provider.parse_webhook(body)
    if not event.event_id:
        raise HTTPException(status_code=400, detail="missing_event_id")
    row = await record_event(db, event)
    if row is None:
        return Response(status_code=200, content="duplicate")
    outcome = await apply_event(db, redis, event, row)
    await db.commit()
    return Response(status_code=200, content=outcome)


@router.post("/admin/billing/reconcile")
async def admin_reconcile(
    identity: AuthIdentity = Depends(require_platform_admin),
    db: AsyncSession = Depends(get_db),
    redis: redis_asyncio.Redis = Depends(get_redis),
) -> dict[str, Any]:
    results = await reconcile_all(db, redis, get_provider())
    await db.commit()
    return {"orgs": len(results), "actions": [r for r in results if r["action"] != "none"]}
