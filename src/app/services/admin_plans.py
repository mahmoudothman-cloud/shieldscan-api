"""Platform-admin operations on the plan catalog and on one org's
entitlements (M12 slice 3; Plans & Billing Review v1.1 §4 "Admin surface").

Catalog edits never mutate a live version in place: ``publish_version``
retires the current (plan, interval) version and inserts the next one,
so every subscriber keeps what they bought and the version rows are the
audit trail. Per-org operations set the RLS context to that org and
write an ``admin.*`` audit row into the org's own log.
"""

from __future__ import annotations

from datetime import date, datetime, timezone
from typing import Any
from uuid import UUID

import redis.asyncio as redis_asyncio
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.tenant_context import set_tenant_context
from app.models.billing import (
    BillingInterval,
    BillingProviderName,
    OrgLimitOverride,
    OrgSubscription,
    Plan,
    PlanVersion,
    SubscriptionStatus,
)
from app.models.identity import Membership, Organization
from app.schemas.admin import (
    OrgAdminDetail,
    OrgSummaryOut,
    OverrideOut,
    PlanAdminOut,
    PlanVersionCreate,
    PlanVersionOut,
    PlanVersionPublished,
    SubscriptionAssign,
    SubscriptionOut,
    VersionDiff,
)
from app.services.audit import AdminAction, audit
from app.services.plans import (
    FEATURE_KEYS,
    LIMIT_KEYS,
    current_subscription,
    get_usage,
    invalidate_limits,
    live_version,
    resolve_limits,
)


class AdminError(Exception):
    def __init__(self, status: int, detail: str) -> None:
        super().__init__(detail)
        self.status = status
        self.detail = detail


# ------------------------------------------------------------------ catalog


async def list_plans(db: AsyncSession) -> list[PlanAdminOut]:
    plans = list(
        (await db.execute(select(Plan).order_by(Plan.rank.nulls_last(), Plan.code))).scalars()
    )
    out: list[PlanAdminOut] = []
    for plan in plans:
        versions = list(
            (
                await db.execute(
                    select(PlanVersion)
                    .where(PlanVersion.plan_id == plan.id)
                    .order_by(PlanVersion.billing_interval, PlanVersion.version)
                )
            ).scalars()
        )
        live = [v for v in versions if v.retired_at is None]
        version_ids = [v.id for v in versions]
        subscribers = await _count_subscribers(db, version_ids) if version_ids else 0
        out.append(
            PlanAdminOut(
                id=plan.id,
                code=plan.code,
                name=plan.name,
                description=plan.description,
                rank=plan.rank,
                is_public=plan.is_public,
                archived_at=plan.archived_at,
                live_versions=[PlanVersionOut.model_validate(v) for v in live],
                version_count=len(versions),
                subscriber_count=subscribers,
            )
        )
    return out


async def _count_subscribers(db: AsyncSession, version_ids: list[UUID]) -> int:
    """Subscribers across all orgs. ``org_subscriptions`` is behind RLS, so
    this walks the organizations (non-tenant) and sets the context per org.
    Fine at tens of orgs; revisit with a materialised count if it hurts."""
    org_ids = list((await db.execute(select(Organization.id))).scalars())
    n = 0
    for org_id in org_ids:
        await set_tenant_context(db, org_id)
        n += int(
            (
                await db.execute(
                    select(func.count(OrgSubscription.id)).where(
                        OrgSubscription.organization_id == org_id,
                        OrgSubscription.plan_version_id.in_(version_ids),
                        OrgSubscription.status != SubscriptionStatus.CANCELED,
                    )
                )
            ).scalar_one()
        )
    return n


async def get_plan(db: AsyncSession, code: str) -> Plan:
    plan = (await db.execute(select(Plan).where(Plan.code == code))).scalar_one_or_none()
    if plan is None:
        raise AdminError(404, "plan_not_found")
    return plan


async def create_plan(
    db: AsyncSession,
    *,
    code: str,
    name: str,
    description: str | None,
    rank: int | None,
    is_public: bool,
) -> Plan:
    if (
        await db.execute(select(Plan.id).where(Plan.code == code))
    ).scalar_one_or_none() is not None:
        raise AdminError(409, "plan_code_exists")
    plan = Plan(code=code, name=name, description=description, rank=rank, is_public=is_public)
    db.add(plan)
    await db.flush()
    return plan


async def patch_plan(
    db: AsyncSession,
    plan: Plan,
    *,
    name: str | None,
    description: str | None,
    rank: int | None,
    is_public: bool | None,
    archived: bool | None,
) -> Plan:
    if name is not None:
        plan.name = name
    if description is not None:
        plan.description = description
    if rank is not None:
        plan.rank = rank
    if is_public is not None:
        plan.is_public = is_public
    if archived is not None:
        if archived and plan.code == "free":
            raise AdminError(409, "free_plan_cannot_be_archived")
        plan.archived_at = datetime.now(timezone.utc) if archived else None
    await db.flush()
    return plan


def _diff(prev: PlanVersion | None, new: PlanVersion) -> list[VersionDiff]:
    if prev is None:
        return [VersionDiff(field="version", before=None, after=new.version)]
    out: list[VersionDiff] = []
    for f in ("price_egp_cents", "price_usd_cents"):
        if getattr(prev, f) != getattr(new, f):
            out.append(VersionDiff(field=f, before=getattr(prev, f), after=getattr(new, f)))
    for k in LIMIT_KEYS:
        if prev.limits.get(k) != new.limits.get(k):
            out.append(
                VersionDiff(field=f"limits.{k}", before=prev.limits.get(k), after=new.limits.get(k))
            )
    for k in FEATURE_KEYS:
        if prev.features.get(k) != new.features.get(k):
            out.append(
                VersionDiff(
                    field=f"features.{k}", before=prev.features.get(k), after=new.features.get(k)
                )
            )
    return out


async def publish_version(
    db: AsyncSession, plan: Plan, body: PlanVersionCreate, *, actor_id: UUID | None
) -> PlanVersionPublished:
    interval = BillingInterval(body.billing_interval)
    if plan.archived_at is not None:
        raise AdminError(409, "plan_archived")
    prev = await live_version(db, plan.code, interval)
    now = datetime.now(timezone.utc)
    last = (
        await db.execute(
            select(func.max(PlanVersion.version)).where(
                PlanVersion.plan_id == plan.id, PlanVersion.billing_interval == interval
            )
        )
    ).scalar_one()
    if prev is not None:
        prev.retired_at = now
        await db.flush()  # the partial unique index wants the old row retired first
    new = PlanVersion(
        plan_id=plan.id,
        version=int(last or 0) + 1,
        billing_interval=interval,
        price_egp_cents=body.price_egp_cents,
        price_usd_cents=body.price_usd_cents,
        limits=body.limits,
        features=body.features,
        paymob_plan_id=None,  # slice 4: created on Paymob when the provider is wired
        paddle_price_id=None,
        effective_from=now,
        change_note=body.change_note,
        created_by=actor_id,
    )
    db.add(new)
    await db.flush()
    return PlanVersionPublished(
        version=PlanVersionOut.model_validate(new),
        retired=PlanVersionOut.model_validate(prev) if prev is not None else None,
        diff=_diff(prev, new),
    )


async def list_versions(db: AsyncSession, plan: Plan) -> list[PlanVersionOut]:
    rows = (
        await db.execute(
            select(PlanVersion)
            .where(PlanVersion.plan_id == plan.id)
            .order_by(PlanVersion.billing_interval, PlanVersion.version.desc())
        )
    ).scalars()
    return [PlanVersionOut.model_validate(v) for v in rows]


# ------------------------------------------------------------------ orgs


async def _org_summary(db: AsyncSession, org: Organization) -> OrgSummaryOut:
    await set_tenant_context(db, org.id)
    members = int(
        (
            await db.execute(
                select(func.count(Membership.id)).where(Membership.organization_id == org.id)
            )
        ).scalar_one()
    )
    sub = await current_subscription(db, org.id)
    plan_code = "free"
    if sub is not None:
        version = await db.get(PlanVersion, sub.plan_version_id)
        if version is not None:
            plan = await db.get(Plan, version.plan_id)
            plan_code = plan.code if plan is not None else plan_code
    return OrgSummaryOut(
        id=org.id,
        name=org.name,
        slug=org.slug,
        created_at=org.created_at,
        members=members,
        plan_code=plan_code,
        subscription_status=sub.status.value if sub is not None else "none",
        provider=sub.provider.value if sub is not None else None,
    )


async def list_orgs(
    db: AsyncSession, *, q: str | None, limit: int, offset: int
) -> tuple[list[OrgSummaryOut], int]:
    stmt = select(Organization)
    if q:
        like = f"%{q.lower()}%"
        stmt = stmt.where(
            func.lower(Organization.name).like(like) | func.lower(Organization.slug).like(like)
        )
    total = int((await db.execute(select(func.count()).select_from(stmt.subquery()))).scalar_one())
    orgs = list(
        (
            await db.execute(
                stmt.order_by(Organization.created_at.desc()).limit(limit).offset(offset)
            )
        ).scalars()
    )
    return [await _org_summary(db, o) for o in orgs], total


async def get_org(db: AsyncSession, org_id: UUID) -> Organization:
    org = await db.get(Organization, org_id)
    if org is None:
        raise AdminError(404, "org_not_found")
    return org


async def org_detail(db: AsyncSession, org: Organization) -> OrgAdminDetail:
    summary = await _org_summary(db, org)  # sets the tenant context
    sub = await current_subscription(db, org.id)
    overrides = list(
        (
            await db.execute(
                select(OrgLimitOverride)
                .where(OrgLimitOverride.organization_id == org.id)
                .order_by(OrgLimitOverride.key)
            )
        ).scalars()
    )
    eff = await resolve_limits(db, org.id)
    usage = await get_usage(db, org.id, eff.period_start_date())
    return OrgAdminDetail(
        org=summary,
        subscription=SubscriptionOut.model_validate(sub) if sub is not None else None,
        overrides=[OverrideOut.model_validate(o) for o in overrides],
        effective_limits=eff.limits,
        effective_features=eff.features,
        usage=usage,
        period_start=eff.period_start_date(),
        period_end=date.fromisoformat(eff.period_end) if eff.period_end else None,
    )


def _validate_override(key: str, value: Any) -> None:
    if key in LIMIT_KEYS:
        if isinstance(value, bool) or not isinstance(value, int) or value < -1:
            raise AdminError(422, "override_value_must_be_int_ge_minus_one")
    elif key == "compliance.frameworks":
        if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
            raise AdminError(422, "override_value_must_be_list_of_slugs")
    elif key in FEATURE_KEYS:
        if not isinstance(value, bool):
            raise AdminError(422, "override_value_must_be_bool")
    else:
        raise AdminError(422, "unknown_override_key")


async def set_override(
    db: AsyncSession,
    redis: redis_asyncio.Redis | None,
    org: Organization,
    *,
    key: str,
    value: Any,
    reason: str | None,
    expires_at: datetime | None,
    actor_id: UUID | None,
) -> OverrideOut:
    _validate_override(key, value)
    await set_tenant_context(db, org.id)
    row = (
        await db.execute(
            select(OrgLimitOverride).where(
                OrgLimitOverride.organization_id == org.id, OrgLimitOverride.key == key
            )
        )
    ).scalar_one_or_none()
    if row is None:
        row = OrgLimitOverride(organization_id=org.id, key=key)
        db.add(row)
    row.value = value
    row.reason = reason
    row.expires_at = expires_at
    row.set_by = actor_id
    await db.flush()
    await audit(
        db,
        organization_id=org.id,
        actor_id=actor_id,
        action=AdminAction.OVERRIDE_SET,
        resource_type="org_limit_override",
        resource_id=row.id,
        details={"key": key, "value": value, "reason": reason or ""},
    )
    await invalidate_limits(redis, org.id)
    return OverrideOut.model_validate(row)


async def remove_override(
    db: AsyncSession,
    redis: redis_asyncio.Redis | None,
    org: Organization,
    *,
    key: str,
    actor_id: UUID | None,
) -> None:
    await set_tenant_context(db, org.id)
    row = (
        await db.execute(
            select(OrgLimitOverride).where(
                OrgLimitOverride.organization_id == org.id, OrgLimitOverride.key == key
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise AdminError(404, "override_not_found")
    await db.delete(row)
    await db.flush()
    await audit(
        db,
        organization_id=org.id,
        actor_id=actor_id,
        action=AdminAction.OVERRIDE_REMOVED,
        resource_type="org_limit_override",
        resource_id=None,
        details={"key": key},
    )
    await invalidate_limits(redis, org.id)


def _add_interval(d: date, interval: BillingInterval) -> date:
    if interval == BillingInterval.YEAR:
        return d.replace(year=d.year + 1)
    month = d.month + 1
    year = d.year + (1 if month == 13 else 0)
    month = 1 if month == 13 else month
    try:
        return d.replace(year=year, month=month)
    except ValueError:  # 29th–31st → clamp
        return d.replace(year=year, month=month, day=28)


async def assign_subscription(
    db: AsyncSession,
    redis: redis_asyncio.Redis | None,
    org: Organization,
    body: SubscriptionAssign,
    *,
    actor_id: UUID | None,
) -> SubscriptionOut:
    interval = BillingInterval(body.billing_interval)
    version = await live_version(db, body.plan_code, interval)
    if version is None:
        raise AdminError(404, "no_live_version_for_plan_and_interval")
    await set_tenant_context(db, org.id)
    now = datetime.now(timezone.utc)
    today = now.date()
    current = await current_subscription(db, org.id)
    if current is not None:
        if (
            current.provider != BillingProviderName.MANUAL
            and current.status == SubscriptionStatus.ACTIVE
        ):
            # A processor-backed subscription must be canceled at the
            # processor first (slice 4 wires that); refusing here keeps the
            # two sides from drifting.
            raise AdminError(409, "cancel_processor_subscription_first")
        current.status = SubscriptionStatus.CANCELED
        current.canceled_at = now
        await db.flush()
    sub = OrgSubscription(
        organization_id=org.id,
        plan_version_id=version.id,
        status=SubscriptionStatus.ACTIVE,
        provider=BillingProviderName.MANUAL,
        current_period_start=today,
        current_period_end=body.period_end
        or (None if body.plan_code == "free" else _add_interval(today, interval)),
        note=body.note,
    )
    db.add(sub)
    await db.flush()
    await audit(
        db,
        organization_id=org.id,
        actor_id=actor_id,
        action=AdminAction.SUBSCRIPTION_ASSIGNED,
        resource_type="org_subscription",
        resource_id=sub.id,
        details={
            "plan_code": body.plan_code,
            "billing_interval": interval.value,
            "reason": body.note or "",
        },
    )
    await invalidate_limits(redis, org.id)
    return SubscriptionOut.model_validate(sub)
