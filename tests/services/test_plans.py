"""Plan catalog + effective limits + usage meters (M12 slice 1)."""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
from uuid import uuid4

import pytest

from app.models.billing import (
    BillingInterval,
    BillingProviderName,
    OrgLimitOverride,
    OrgSubscription,
    SubscriptionStatus,
)
from app.models.identity import Organization
from app.models.scans import ScanType
from app.services.plans import (
    DEFAULT_LADDER,
    LIMIT_KEYS,
    UNLIMITED,
    ensure_free_subscription,
    get_effective_limits,
    get_usage,
    increment_usage,
    invalidate_limits,
    live_version,
    record_scan_usage,
    resolve_limits,
)
from tests.conftest import use_org


async def _org(db_session, tag: str) -> Organization:
    org = Organization(name=f"{tag} Org", slug=f"{tag}-{uuid4().hex[:8]}")
    db_session.add(org)
    await db_session.flush()
    await use_org(db_session, org.id)
    return org


def test_ladder_is_well_formed():
    codes = [e.code for e in DEFAULT_LADDER]
    assert codes == ["free", "starter", "growth", "business", "enterprise"]
    for entry in DEFAULT_LADDER:
        assert set(entry.limits) == set(LIMIT_KEYS)
        assert all(isinstance(v, int) for v in entry.limits.values())
    starter = next(e for e in DEFAULT_LADDER if e.code == "starter")
    assert starter.price_egp_cents == 99_900 and starter.price_usd_cents == 2_900
    business = next(e for e in DEFAULT_LADDER if e.code == "business")
    assert business.limits["scans.full.per_period"] == 500  # capped, not unlimited (review §3)
    assert business.limits["projects.max"] == UNLIMITED


@pytest.mark.asyncio
async def test_seed_has_live_versions_for_both_intervals(db_session):
    assert await live_version(db_session, "free", BillingInterval.MONTH) is not None
    assert (
        await live_version(db_session, "free", BillingInterval.YEAR) is None
    )  # free has no annual
    yearly = await live_version(db_session, "growth", BillingInterval.YEAR)
    monthly = await live_version(db_session, "growth", BillingInterval.MONTH)
    assert yearly is not None and monthly is not None
    assert yearly.price_egp_cents == 10 * monthly.price_egp_cents


@pytest.mark.asyncio
async def test_org_without_subscription_resolves_to_free(db_session):
    org = await _org(db_session, "nosub")
    eff = await resolve_limits(db_session, org.id, today=date(2026, 11, 11))
    assert eff.plan_code == "free"
    assert eff.subscription_status == "active"
    assert eff.period_start == "2026-11-01" and eff.period_end == "2026-12-01"
    assert eff.limit("projects.max") == 1
    assert eff.feature("ai_fix") is False
    assert eff.allows("projects.max", 0) and not eff.allows("projects.max", 1)


@pytest.mark.asyncio
async def test_ensure_free_subscription_is_idempotent(db_session):
    org = await _org(db_session, "free")
    a = await ensure_free_subscription(db_session, org.id)
    b = await ensure_free_subscription(db_session, org.id)
    assert a.id == b.id
    assert a.provider == BillingProviderName.MANUAL and a.status == SubscriptionStatus.ACTIVE


@pytest.mark.asyncio
async def test_active_subscription_uses_its_version_and_period(db_session):
    org = await _org(db_session, "growth")
    growth = await live_version(db_session, "growth")
    assert growth is not None
    db_session.add(
        OrgSubscription(
            organization_id=org.id,
            plan_version_id=growth.id,
            status=SubscriptionStatus.ACTIVE,
            provider=BillingProviderName.PAYMOB,
            current_period_start=date(2026, 11, 5),
            current_period_end=date(2026, 12, 5),
        )
    )
    await db_session.flush()
    eff = await resolve_limits(db_session, org.id, today=date(2026, 11, 11))
    assert eff.plan_code == "growth"
    assert eff.period_start == "2026-11-05" and eff.period_end == "2026-12-05"
    assert eff.limit("scans.full.per_period") == 100
    assert eff.feature("cross_layer") is True
    assert "egypt_pdpl" in eff.feature("compliance.frameworks")


@pytest.mark.asyncio
async def test_suspended_subscription_falls_back_to_free(db_session):
    org = await _org(db_session, "susp")
    business = await live_version(db_session, "business")
    assert business is not None
    db_session.add(
        OrgSubscription(
            organization_id=org.id,
            plan_version_id=business.id,
            status=SubscriptionStatus.SUSPENDED,
            provider=BillingProviderName.PAYMOB,
            current_period_start=date(2026, 10, 1),
            current_period_end=date(2026, 11, 1),
        )
    )
    await db_session.flush()
    eff = await resolve_limits(db_session, org.id, today=date(2026, 11, 11))
    assert eff.plan_code == "free"
    assert eff.subscription_status == "suspended"
    assert eff.period_start == "2026-11-01"  # calendar period, not the dead one


@pytest.mark.asyncio
async def test_overrides_apply_and_expire(db_session):
    org = await _org(db_session, "ovr")
    now = datetime.now(timezone.utc)
    db_session.add_all(
        [
            OrgLimitOverride(
                organization_id=org.id, key="projects.max", value=7, reason="design partner"
            ),
            OrgLimitOverride(organization_id=org.id, key="ai_fix", value=True),
            OrgLimitOverride(
                organization_id=org.id,
                key="scans.full.per_period",
                value=99,
                expires_at=now - timedelta(days=1),
            ),
            OrgLimitOverride(organization_id=org.id, key="not.a.key", value=1),
        ]
    )
    await db_session.flush()
    eff = await resolve_limits(db_session, org.id)
    assert eff.limit("projects.max") == 7
    assert eff.feature("ai_fix") is True
    assert eff.limit("scans.full.per_period") == 1  # expired override ignored
    assert sorted(eff.overrides) == ["ai_fix", "projects.max"]


@pytest.mark.asyncio
async def test_cache_round_trip_and_invalidation(db_session, fake_redis):
    org = await _org(db_session, "cache")
    first = await get_effective_limits(db_session, fake_redis, org.id)
    assert first.plan_code == "free"
    # A write the cache does not know about...
    db_session.add(OrgLimitOverride(organization_id=org.id, key="projects.max", value=42))
    await db_session.flush()
    cached = await get_effective_limits(db_session, fake_redis, org.id)
    assert cached.limit("projects.max") == 1  # still the cached answer
    await invalidate_limits(fake_redis, org.id)
    fresh = await get_effective_limits(db_session, fake_redis, org.id)
    assert fresh.limit("projects.max") == 42


@pytest.mark.asyncio
async def test_usage_counters_upsert_and_scan_mapping(db_session):
    org = await _org(db_session, "usage")
    period = date(2026, 11, 1)
    assert await increment_usage(db_session, org.id, "scans.full.per_period", period) == 1
    assert await increment_usage(db_session, org.id, "scans.full.per_period", period) == 2
    eff = await resolve_limits(db_session, org.id, today=date(2026, 11, 11))
    await record_scan_usage(db_session, eff, org.id, ScanType.QUICK)
    await record_scan_usage(db_session, eff, org.id, ScanType.API)  # counts as a full scan
    usage = await get_usage(db_session, org.id, period)
    assert usage["scans.full.per_period"] == 3
    assert usage["scans.quick.per_period"] == 1
    assert usage["scans.mobile.per_period"] == 0
    assert await get_usage(db_session, org.id, date(2026, 10, 1)) == {
        k: 0 for k in LIMIT_KEYS if k.endswith(".per_period")
    }
