"""Plan catalog: default ladder, effective-limit resolution, usage meters.

(M12 slice 1; Plans & Billing Review v1.1 §3–§4.)

``get_effective_limits`` is the ONE way code learns what an org may do.
It starts from the org's subscription's plan version, lays non-expired
per-org overrides on top, and caches the result in Redis for 60 s
(``invalidate_limits`` on every write to the catalog or the org's
subscription/overrides). Callers ask ``limits["scans.full.per_period"]``
or ``features["ai_fix"]`` — never "is this org on Growth".

Usage is metered in ``usage_counters`` per (org, key, period). The period
is the subscription's current period when it has one; otherwise the UTC
calendar month. ``increment_usage`` runs in the caller's transaction so a
scan that fails to dispatch is never counted.
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import date, datetime, timezone
from typing import Any
from uuid import UUID

import redis.asyncio as redis_asyncio
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.billing import (
    BillingInterval,
    BillingProviderName,
    OrgLimitOverride,
    OrgSubscription,
    Plan,
    PlanVersion,
    SubscriptionStatus,
    UsageCounter,
)
from app.models.scans import ScanType

logger = logging.getLogger(__name__)

UNLIMITED = -1

LIMIT_KEYS: tuple[str, ...] = (
    "users.max",
    "projects.max",
    "api_keys.max",
    "scans.quick.per_period",
    "scans.full.per_period",
    "scans.mobile.per_period",
    "scans.full_spectrum.per_period",
    "recon.subdomains.max",
)
FEATURE_KEYS: tuple[str, ...] = (
    "ai_fix",
    "cross_layer",
    "compliance.frameworks",
    "cli_write",
    "priority_queue",
    "sso",
)

# Which usage key a scan type counts against.
SCAN_USAGE_KEY: dict[ScanType, str] = {
    ScanType.QUICK: "scans.quick.per_period",
    ScanType.FULL_WEB: "scans.full.per_period",
    ScanType.FULL_WEB_SOURCE: "scans.full.per_period",
    ScanType.API: "scans.full.per_period",
    ScanType.CONTAINER: "scans.full.per_period",
    ScanType.MOBILE: "scans.mobile.per_period",
    ScanType.FULL_SPECTRUM: "scans.full_spectrum.per_period",
}

_CACHE_TTL_S = 60
_CACHE_PREFIX = "shieldscan:limits:"

# Statuses under which the org gets its plan's limits. PAST_DUE keeps them
# through the grace window; SUSPENDED and CANCELED fall back to Free.
_ENTITLED_STATUSES = frozenset(
    {SubscriptionStatus.ACTIVE, SubscriptionStatus.TRIALING, SubscriptionStatus.PAST_DUE}
)


# ------------------------------------------------------------ default ladder


def _limits(
    *,
    users: int,
    projects: int,
    api_keys: int,
    quick: int,
    full: int,
    mobile: int,
    full_spectrum: int,
    recon: int,
) -> dict[str, int]:
    return {
        "users.max": users,
        "projects.max": projects,
        "api_keys.max": api_keys,
        "scans.quick.per_period": quick,
        "scans.full.per_period": full,
        "scans.mobile.per_period": mobile,
        "scans.full_spectrum.per_period": full_spectrum,
        "recon.subdomains.max": recon,
    }


def _features(
    *,
    ai_fix: bool,
    cross_layer: bool,
    frameworks: list[str],
    cli_write: bool,
    priority_queue: bool = False,
    sso: bool = False,
) -> dict[str, Any]:
    return {
        "ai_fix": ai_fix,
        "cross_layer": cross_layer,
        "compliance.frameworks": frameworks,
        "cli_write": cli_write,
        "priority_queue": priority_queue,
        "sso": sso,
    }


@dataclass(frozen=True)
class LadderEntry:
    code: str
    name: str
    rank: int
    description: str
    price_egp_cents: int  # monthly, gross (14% VAT inside)
    price_usd_cents: int  # monthly, gross
    limits: dict[str, int]
    features: dict[str, Any]
    is_public: bool = True


# Review v1.1 §3 ladder. Prices are monthly; annual = 10 × monthly.
DEFAULT_LADDER: tuple[LadderEntry, ...] = (
    LadderEntry(
        code="free",
        name="Free",
        rank=0,
        description="One project, the passive quick scan and one full scan a month.",
        price_egp_cents=0,
        price_usd_cents=0,
        limits=_limits(
            users=1, projects=1, api_keys=1, quick=5, full=1, mobile=0, full_spectrum=0, recon=10
        ),
        features=_features(ai_fix=False, cross_layer=False, frameworks=[], cli_write=False),
    ),
    LadderEntry(
        code="starter",
        name="Starter",
        rank=10,
        description="Full DAST and infrastructure scans with AI fixes for a small team.",
        price_egp_cents=99_900,
        price_usd_cents=2_900,
        limits=_limits(
            users=3, projects=5, api_keys=5, quick=50, full=10, mobile=0, full_spectrum=0, recon=50
        ),
        features=_features(ai_fix=True, cross_layer=False, frameworks=[], cli_write=True),
    ),
    LadderEntry(
        code="growth",
        name="Growth",
        rank=20,
        description="Cross-layer correlation, ISO 27001 and Egypt PDPL mapping, mobile scans.",
        price_egp_cents=299_900,
        price_usd_cents=9_900,
        limits=_limits(
            users=10,
            projects=25,
            api_keys=20,
            quick=500,
            full=100,
            mobile=2,
            full_spectrum=0,
            recon=100,
        ),
        features=_features(
            ai_fix=True,
            cross_layer=True,
            frameworks=["iso27001", "egypt_pdpl"],
            cli_write=True,
            priority_queue=True,
        ),
    ),
    LadderEntry(
        code="business",
        name="Business",
        rank=30,
        description="Unlimited users and projects, every compliance framework, full-spectrum scans.",
        price_egp_cents=1_299_900,
        price_usd_cents=29_900,
        limits=_limits(
            users=UNLIMITED,
            projects=UNLIMITED,
            api_keys=UNLIMITED,
            quick=UNLIMITED,
            full=500,
            mobile=10,
            full_spectrum=50,
            recon=500,
        ),
        features=_features(
            ai_fix=True,
            cross_layer=True,
            frameworks=["iso27001", "soc2", "pci_dss", "egypt_pdpl"],
            cli_write=True,
            priority_queue=True,
        ),
    ),
    LadderEntry(
        code="enterprise",
        name="Enterprise",
        rank=40,
        description="Per-contract limits, SSO, dedicated support.",
        price_egp_cents=0,
        price_usd_cents=0,
        limits=_limits(
            users=UNLIMITED,
            projects=UNLIMITED,
            api_keys=UNLIMITED,
            quick=UNLIMITED,
            full=UNLIMITED,
            mobile=UNLIMITED,
            full_spectrum=UNLIMITED,
            recon=UNLIMITED,
        ),
        features=_features(
            ai_fix=True,
            cross_layer=True,
            frameworks=["iso27001", "soc2", "pci_dss", "egypt_pdpl"],
            cli_write=True,
            priority_queue=True,
            sso=True,
        ),
        is_public=False,  # custom — not on the self-serve pricing page
    ),
)

ANNUAL_MONTHS = 10  # annual price = 10 × monthly


def default_ladder_rows(now: datetime) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """(plan rows, plan_version rows) for the seed migration and tests.
    Plan ids are deterministic so the two lists line up without a round trip."""
    import uuid

    plans: list[dict[str, Any]] = []
    versions: list[dict[str, Any]] = []
    for entry in DEFAULT_LADDER:
        plan_id = uuid.uuid5(uuid.NAMESPACE_URL, f"shieldscan:plan:{entry.code}")
        plans.append(
            {
                "id": plan_id,
                "code": entry.code,
                "name": entry.name,
                "description": entry.description,
                "rank": entry.rank,
                "is_public": entry.is_public,
                "archived_at": None,
                "created_at": now,
                "updated_at": now,
            }
        )
        intervals: list[tuple[BillingInterval, int]] = [(BillingInterval.MONTH, 1)]
        if entry.price_egp_cents > 0:
            intervals.append((BillingInterval.YEAR, ANNUAL_MONTHS))
        for interval, mult in intervals:
            versions.append(
                {
                    "id": uuid.uuid5(
                        uuid.NAMESPACE_URL,
                        f"shieldscan:plan_version:{entry.code}:{interval.value}:1",
                    ),
                    "plan_id": plan_id,
                    "version": 1,
                    "billing_interval": interval,
                    "price_egp_cents": entry.price_egp_cents * mult,
                    "price_usd_cents": entry.price_usd_cents * mult,
                    "limits": entry.limits,
                    "features": entry.features,
                    "paymob_plan_id": None,
                    "paddle_price_id": None,
                    "effective_from": now,
                    "retired_at": None,
                    "change_note": "Seed: Plans & Billing Review v1.1 §3",
                    "created_at": now,
                    "updated_at": now,
                }
            )
    return plans, versions


# ------------------------------------------------------------ resolution


@dataclass
class EffectiveLimits:
    plan_code: str
    plan_name: str
    plan_version_id: str | None
    billing_interval: str
    subscription_status: str
    period_start: str  # ISO date
    period_end: str | None
    limits: dict[str, int] = field(default_factory=dict)
    features: dict[str, Any] = field(default_factory=dict)
    overrides: list[str] = field(default_factory=list)  # keys an override touched

    def limit(self, key: str) -> int:
        return int(self.limits.get(key, 0))

    def allows(self, key: str, current: int) -> bool:
        cap = self.limit(key)
        return cap == UNLIMITED or current < cap

    def feature(self, key: str) -> Any:
        return self.features.get(key, False)

    def period_start_date(self) -> date:
        return date.fromisoformat(self.period_start)


def _calendar_period(today: date) -> tuple[date, date]:
    start = today.replace(day=1)
    end = (
        start.replace(year=start.year + 1, month=1)
        if start.month == 12
        else start.replace(month=start.month + 1)
    )
    return start, end


async def live_version(
    db: AsyncSession, code: str, interval: BillingInterval = BillingInterval.MONTH
) -> PlanVersion | None:
    return (
        await db.execute(
            select(PlanVersion)
            .join(Plan, Plan.id == PlanVersion.plan_id)
            .where(
                Plan.code == code,
                PlanVersion.billing_interval == interval,
                PlanVersion.retired_at.is_(None),
            )
        )
    ).scalar_one_or_none()


async def current_subscription(db: AsyncSession, org_id: UUID) -> OrgSubscription | None:
    """The org's one non-canceled subscription, or None (→ Free)."""
    return (
        await db.execute(
            select(OrgSubscription).where(
                OrgSubscription.organization_id == org_id,
                OrgSubscription.status != SubscriptionStatus.CANCELED,
            )
        )
    ).scalar_one_or_none()


async def ensure_free_subscription(
    db: AsyncSession, org_id: UUID, *, today: date | None = None
) -> OrgSubscription:
    """Give an org its Free row if it has none. Called at registration;
    the resolver tolerates its absence so this is an invariant, not a
    precondition. Flushes; does not commit."""
    existing = await current_subscription(db, org_id)
    if existing is not None:
        return existing
    free = await live_version(db, "free")
    if free is None:  # catalog not seeded (tests before the seed fixture)
        raise RuntimeError("plan catalog has no live free version")
    start, _ = _calendar_period(today or datetime.now(timezone.utc).date())
    sub = OrgSubscription(
        organization_id=org_id,
        plan_version_id=free.id,
        status=SubscriptionStatus.ACTIVE,
        provider=BillingProviderName.MANUAL,
        current_period_start=start,
        current_period_end=None,
    )
    db.add(sub)
    await db.flush()
    return sub


async def resolve_limits(
    db: AsyncSession, org_id: UUID, *, today: date | None = None
) -> EffectiveLimits:
    """Uncached resolution. Runs inside the org's tenant context."""
    today = today or datetime.now(timezone.utc).date()
    sub = await current_subscription(db, org_id)
    version: PlanVersion | None = None
    status = SubscriptionStatus.ACTIVE
    if sub is not None and sub.status in _ENTITLED_STATUSES:
        version = await db.get(PlanVersion, sub.plan_version_id)
        status = sub.status
    elif sub is not None:
        status = sub.status
    if version is None:
        version = await live_version(db, "free")
    if version is None:
        raise RuntimeError("plan catalog has no live free version")
    plan = await db.get(Plan, version.plan_id)
    assert plan is not None

    if sub is not None and sub.status in _ENTITLED_STATUSES and sub.current_period_end is not None:
        p_start, p_end = sub.current_period_start, sub.current_period_end
    else:
        p_start, p_end = _calendar_period(today)

    limits: dict[str, int] = {k: int(version.limits.get(k, 0)) for k in LIMIT_KEYS}
    features: dict[str, Any] = {k: version.features.get(k, False) for k in FEATURE_KEYS}
    touched: list[str] = []
    now = datetime.now(timezone.utc)
    overrides = (
        await db.execute(select(OrgLimitOverride).where(OrgLimitOverride.organization_id == org_id))
    ).scalars()
    for ov in overrides:
        if ov.expires_at is not None and ov.expires_at <= now:
            continue
        if ov.key in LIMIT_KEYS:
            if not isinstance(ov.value, (int, float, str)) or isinstance(ov.value, bool):
                continue
            limits[ov.key] = int(ov.value)
        elif ov.key in FEATURE_KEYS:
            features[ov.key] = ov.value
        else:
            continue
        touched.append(ov.key)

    return EffectiveLimits(
        plan_code=plan.code,
        plan_name=plan.name,
        plan_version_id=str(version.id),
        billing_interval=version.billing_interval.value,
        subscription_status=status.value,
        period_start=p_start.isoformat(),
        period_end=p_end.isoformat() if p_end else None,
        limits=limits,
        features=features,
        overrides=touched,
    )


def _cache_key(org_id: UUID) -> str:
    return f"{_CACHE_PREFIX}{org_id}"


async def get_effective_limits(
    db: AsyncSession, redis: redis_asyncio.Redis | None, org_id: UUID
) -> EffectiveLimits:
    """Cached resolution (60 s). Redis failures degrade to uncached."""
    if redis is not None:
        try:
            raw = await redis.get(_cache_key(org_id))
        except Exception:  # noqa: BLE001 — cache is best-effort
            raw = None
        if raw:
            try:
                return EffectiveLimits(**json.loads(raw))
            except (TypeError, ValueError):
                pass
    eff = await resolve_limits(db, org_id)
    if redis is not None:
        try:
            await redis.set(_cache_key(org_id), json.dumps(asdict(eff)), ex=_CACHE_TTL_S)
        except Exception:  # noqa: BLE001
            logger.debug("limits cache write failed for org %s", org_id, exc_info=True)
    return eff


async def invalidate_limits(redis: redis_asyncio.Redis | None, org_id: UUID) -> None:
    if redis is None:
        return
    try:
        await redis.delete(_cache_key(org_id))
    except Exception:  # noqa: BLE001
        logger.debug("limits cache invalidate failed for org %s", org_id, exc_info=True)


# ------------------------------------------------------------ usage meters


async def increment_usage(
    db: AsyncSession, org_id: UUID, key: str, period_start: date, by: int = 1
) -> int:
    """Atomic upsert-increment in the caller's transaction. Returns the new count."""
    now = datetime.now(timezone.utc)
    stmt = (
        pg_insert(UsageCounter)
        .values(
            organization_id=org_id,
            key=key,
            period_start=period_start,
            count=by,
            created_at=now,
            updated_at=now,
        )
        .on_conflict_do_update(
            constraint="uq_usage_counters_org_key_period",
            set_={"count": UsageCounter.count + by, "updated_at": now},
        )
        .returning(UsageCounter.count)
    )
    return int((await db.execute(stmt)).scalar_one())


async def get_usage(db: AsyncSession, org_id: UUID, period_start: date) -> dict[str, int]:
    rows = (
        await db.execute(
            select(UsageCounter.key, UsageCounter.count).where(
                UsageCounter.organization_id == org_id, UsageCounter.period_start == period_start
            )
        )
    ).all()
    usage = {k: 0 for k in LIMIT_KEYS if k.endswith(".per_period")}
    for key, count in rows:
        usage[key] = int(count)
    return usage


async def record_scan_usage(
    db: AsyncSession, eff: EffectiveLimits, org_id: UUID, scan_type: ScanType
) -> int:
    """Count a scan against its meter (public scans are never metered)."""
    key = SCAN_USAGE_KEY[scan_type]
    return await increment_usage(db, org_id, key, eff.period_start_date())
