"""Plan catalog + per-org billing summary (M12 slice 1).

``GET /plans`` is public and unauthenticated: the pricing page, the
register page and the in-app upgrade dialog all render from it, so a
price or limit edited by a platform admin shows everywhere without a
deploy. ``GET /orgs/{org_id}/billing/summary`` is the org's effective
limits plus this period's usage — what the dashboard's usage bars and
the CLI's 402 explanations read.
"""

from __future__ import annotations

from datetime import date
from uuid import UUID

import redis.asyncio as redis_asyncio
from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import AuthIdentity, get_db, require_org_membership
from app.models.billing import Plan, PlanVersion
from app.redis_client import get_redis
from app.schemas.plans import (
    BillingSummaryResponse,
    PlanCatalogResponse,
    PlanPrice,
    PlanPublic,
)
from app.services.plans import get_effective_limits, get_usage

router = APIRouter(tags=["plans"])


@router.get("/plans", response_model=PlanCatalogResponse)
async def list_plans(db: AsyncSession = Depends(get_db)) -> PlanCatalogResponse:
    rows = (
        await db.execute(
            select(Plan, PlanVersion)
            .join(PlanVersion, PlanVersion.plan_id == Plan.id)
            .where(
                Plan.is_public.is_(True),
                Plan.archived_at.is_(None),
                PlanVersion.retired_at.is_(None),
            )
            .order_by(Plan.rank, Plan.code, PlanVersion.billing_interval)
        )
    ).all()
    by_code: dict[str, PlanPublic] = {}
    for plan, version in rows:
        entry = by_code.get(plan.code)
        if entry is None:
            entry = PlanPublic(
                code=plan.code,
                name=plan.name,
                description=plan.description,
                rank=plan.rank,
                prices=[],
            )
            by_code[plan.code] = entry
        entry.prices.append(
            PlanPrice(
                version_id=version.id,
                billing_interval=version.billing_interval.value,
                price_egp_cents=version.price_egp_cents,
                price_usd_cents=version.price_usd_cents,
                limits=version.limits,
                features=version.features,
            )
        )
    return PlanCatalogResponse(plans=list(by_code.values()))


@router.get("/orgs/{org_id}/billing/summary", response_model=BillingSummaryResponse)
async def billing_summary(
    org_id: UUID,
    identity: AuthIdentity = Depends(require_org_membership()),
    db: AsyncSession = Depends(get_db),
    redis: redis_asyncio.Redis = Depends(get_redis),
) -> BillingSummaryResponse:
    eff = await get_effective_limits(db, redis, org_id)
    usage = await get_usage(db, org_id, eff.period_start_date())
    return BillingSummaryResponse(
        plan_code=eff.plan_code,
        plan_name=eff.plan_name,
        billing_interval=eff.billing_interval,
        subscription_status=eff.subscription_status,
        period_start=eff.period_start_date(),
        period_end=date.fromisoformat(eff.period_end) if eff.period_end else None,
        limits=eff.limits,
        features=eff.features,
        usage=usage,
        overrides=eff.overrides,
    )
