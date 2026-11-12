"""Plan-limit enforcement (M12 slice 2; Plans & Billing Review v1.1 §4).

One error shape for every limit the product enforces, so the dashboard,
the CLI and the MCP server render it the same way::

    402 Payment Required
    {"detail": {"error": "plan_limit_reached",
                "key": "projects.max", "limit": 1, "current": 1,
                "plan": "free", "upgrade_url": "<APP_BASE_URL>/settings/billing"}}

Three checks:

* ``require_capacity`` — a hard cap on a live count (projects, members,
  API keys): refuses when ``current >= limit``.
* ``require_scan_capacity`` — the per-period meter for a scan type,
  read from ``usage_counters`` for the org's current period.
* ``require_feature`` — a boolean or list feature (``ai_fix``,
  ``cross_layer``, ``cli_write``, ``compliance.frameworks``).

Everything reads ``get_effective_limits`` (60 s cache), so a plan change
is visible within a minute without a deploy. Downgrades never delete:
an org over a new cap keeps what it has and cannot add more.

``settings.PLAN_LIMITS_ENFORCED=false`` turns every check here (and the
pipeline's feature gates) into a pass-through — the incident kill switch.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

import redis.asyncio as redis_asyncio
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.scans import ScanType
from app.services.plans import (
    SCAN_USAGE_KEY,
    UNLIMITED,
    EffectiveLimits,
    get_effective_limits,
    get_usage,
)

PLAN_LIMIT_ERROR = "plan_limit_reached"


def enforced() -> bool:
    return bool(settings.PLAN_LIMITS_ENFORCED)


def feature_on(eff: EffectiveLimits, key: str) -> bool:
    """A feature gate for non-request code (the AI pipeline): honours the
    kill switch like the request-time checks."""
    return bool(eff.feature(key)) or not enforced()


def upgrade_url() -> str:
    return f"{settings.APP_BASE_URL.rstrip('/')}/settings/billing"


def plan_limit_exception(
    eff: EffectiveLimits, key: str, *, limit: Any, current: Any
) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_402_PAYMENT_REQUIRED,
        detail={
            "error": PLAN_LIMIT_ERROR,
            "key": key,
            "limit": limit,
            "current": current,
            "plan": eff.plan_code,
            "upgrade_url": upgrade_url(),
        },
    )


async def require_capacity(
    db: AsyncSession,
    redis: redis_asyncio.Redis | None,
    org_id: UUID,
    key: str,
    current: int,
) -> EffectiveLimits:
    """Refuse when ``current`` already fills the cap for ``key``."""
    eff = await get_effective_limits(db, redis, org_id)
    if enforced() and not eff.allows(key, current):
        raise plan_limit_exception(eff, key, limit=eff.limit(key), current=current)
    return eff


async def require_scan_capacity(
    db: AsyncSession,
    redis: redis_asyncio.Redis | None,
    org_id: UUID,
    scan_type: ScanType,
) -> EffectiveLimits:
    """Refuse when this period's meter for the scan type is at its cap."""
    eff = await get_effective_limits(db, redis, org_id)
    key = SCAN_USAGE_KEY[scan_type]
    cap = eff.limit(key)
    if cap == UNLIMITED or not enforced():
        return eff
    used = (await get_usage(db, org_id, eff.period_start_date())).get(key, 0)
    if used >= cap:
        raise plan_limit_exception(eff, key, limit=cap, current=used)
    return eff


async def require_feature(
    db: AsyncSession,
    redis: redis_asyncio.Redis | None,
    org_id: UUID,
    key: str,
    *,
    member: str | None = None,
) -> EffectiveLimits:
    """Refuse when a boolean feature is off, or ``member`` is not in a
    list feature (``compliance.frameworks``)."""
    eff = await get_effective_limits(db, redis, org_id)
    if not enforced():
        return eff
    value = eff.feature(key)
    if member is not None:
        allowed = value if isinstance(value, list) else []
        if member not in allowed:
            raise plan_limit_exception(eff, key, limit=allowed, current=member)
    elif not value:
        raise plan_limit_exception(eff, key, limit=False, current=False)
    return eff


def clamp_subdomain_limit(eff: EffectiveLimits, requested: int) -> int:
    """Recon never expands past the plan's subdomain cap; the request's
    value is kept when it is lower (no error — a silent clamp is the
    documented behaviour for a soft ceiling)."""
    cap = eff.limit("recon.subdomains.max")
    if cap == UNLIMITED or not enforced():
        return requested
    return min(requested, max(cap, 1))
