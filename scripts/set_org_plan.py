"""One-off until the admin API lands (M12 slice 3): put an org on a plan.

    poetry run python scripts/set_org_plan.py <org-slug> <plan-code> [--interval month|year] [--note "..."]

Creates a MANUAL, ACTIVE subscription on the plan's live version for the
given interval, canceling any current non-canceled subscription first,
and clears the org's limits cache. Period = today → +1 month / +1 year.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sqlalchemy import select  # noqa: E402

from app.db import AsyncSessionLocal  # noqa: E402
from app.db.tenant_context import set_tenant_context  # noqa: E402
from app.models.billing import (  # noqa: E402
    BillingInterval,
    BillingProviderName,
    OrgSubscription,
    SubscriptionStatus,
)
from app.models.identity import Organization  # noqa: E402
from app.redis_client import close_redis, init_redis  # noqa: E402
from app.services.plans import current_subscription, invalidate_limits, live_version  # noqa: E402


def _add_interval(d, interval: BillingInterval):
    if interval == BillingInterval.YEAR:
        return d.replace(year=d.year + 1)
    month = d.month + 1
    year = d.year + (1 if month == 13 else 0)
    month = 1 if month == 13 else month
    try:
        return d.replace(year=year, month=month)
    except ValueError:  # 31st → last day of next month
        return d.replace(year=year, month=month, day=28)


async def main(slug: str, code: str, interval: BillingInterval, note: str | None) -> None:
    now = datetime.now(timezone.utc)
    today = now.date()
    async with AsyncSessionLocal() as db:
        org = (
            await db.execute(select(Organization).where(Organization.slug == slug))
        ).scalar_one_or_none()
        if org is None:
            raise SystemExit(f"no org with slug {slug!r}")
        await set_tenant_context(db, org.id)
        version = await live_version(db, code, interval)
        if version is None:
            raise SystemExit(f"no live {interval.value} version for plan {code!r}")
        current = await current_subscription(db, org.id)
        if current is not None:
            current.status = SubscriptionStatus.CANCELED
            current.canceled_at = now
            await db.flush()
        db.add(
            OrgSubscription(
                organization_id=org.id,
                plan_version_id=version.id,
                status=SubscriptionStatus.ACTIVE,
                provider=BillingProviderName.MANUAL,
                current_period_start=today,
                current_period_end=_add_interval(today, interval),
                note=note,
            )
        )
        await db.commit()
    redis = await init_redis()
    await invalidate_limits(redis, org.id)
    await close_redis()
    print(
        f"{slug}: now on {code} ({interval.value}), period {today} → {_add_interval(today, interval)}"
    )


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("slug")
    ap.add_argument("code")
    ap.add_argument("--interval", choices=["month", "year"], default="month")
    ap.add_argument("--note")
    a = ap.parse_args()
    asyncio.run(main(a.slug, a.code, BillingInterval(a.interval), a.note))
