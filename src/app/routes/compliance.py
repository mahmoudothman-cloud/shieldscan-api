"""Compliance endpoints (M10.C; Task 10.5; SPEC §6 — 3 compliance routes).

Three org-scoped GETs:
- ``router``               /orgs/{org_id}/compliance/frameworks   (global list)
- ``router``               /orgs/{org_id}/compliance/posture      (org-wide)
- ``scan_compliance_router`` /orgs/{org_id}/scans/{scan_id}/compliance/{fw}

Tenancy via ``require_org_membership()``. The per-scan endpoint reuses
``_load_terminal_scan`` from routes/reports.py (404 org-scoped + 409 non-
terminal). All ungated (tier-enforcement forward-pinned to billing, per the
M10.A /fix + M10.B report precedent). No audit rows — all GETs (V-JJH).
The compliance reference tables are global (no RLS); posture reads the org's
tenant-scoped vulnerabilities under the request's RLS context.
"""

from __future__ import annotations

from uuid import UUID

import redis.asyncio as redis_asyncio
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import AuthIdentity, get_db, require_org_membership
from app.models.compliance import ComplianceControl, ComplianceFramework
from app.redis_client import get_redis
from app.routes.reports import _load_terminal_scan
from app.services.compliance.mapper import (
    FrameworkNotFoundError,
    compute_org_posture,
    compute_scan_posture,
)
from app.services.plan_enforcement import enforced, plan_limit_exception, require_feature
from app.services.plans import EffectiveLimits, get_effective_limits


def _plan_frameworks(eff: EffectiveLimits) -> list[str]:
    value = eff.feature("compliance.frameworks")
    return list(value) if isinstance(value, list) else []


router = APIRouter(prefix="/orgs/{org_id}/compliance", tags=["compliance"])
scan_compliance_router = APIRouter(
    prefix="/orgs/{org_id}/scans/{scan_id}/compliance", tags=["compliance"]
)


@router.get("/frameworks")
async def list_frameworks(
    org_id: UUID,
    identity: AuthIdentity = Depends(require_org_membership()),
    db: AsyncSession = Depends(get_db),
    redis: redis_asyncio.Redis = Depends(get_redis),
) -> dict:
    eff = await get_effective_limits(db, redis, org_id)
    in_plan = set(_plan_frameworks(eff))
    frameworks = (await db.execute(select(ComplianceFramework))).scalars().all()
    out = []
    for fw in frameworks:
        controls = (
            (
                await db.execute(
                    select(ComplianceControl).where(ComplianceControl.framework_id == fw.id)
                )
            )
            .scalars()
            .all()
        )
        out.append(
            {
                "slug": fw.slug,
                "name": fw.name,
                "version": fw.version,
                "in_plan": fw.slug in in_plan,
                "controls": [
                    {
                        "control_id": c.control_id,
                        "title": c.title,
                        "description": c.description,
                    }
                    for c in controls
                ],
            }
        )
    return {"frameworks": out}


@router.get("/posture")
async def get_org_posture(
    org_id: UUID,
    identity: AuthIdentity = Depends(require_org_membership()),
    db: AsyncSession = Depends(get_db),
    redis: redis_asyncio.Redis = Depends(get_redis),
) -> dict:
    # M12 slice 2: only the plan's frameworks are reported; none → 402.
    eff = await get_effective_limits(db, redis, org_id)
    allowed = _plan_frameworks(eff)
    posture = await compute_org_posture(db=db, org_id=org_id)
    if not enforced():
        return posture
    if not allowed:
        raise plan_limit_exception(eff, "compliance.frameworks", limit=[], current=None)
    posture["frameworks"] = [f for f in posture["frameworks"] if f["slug"] in allowed]
    return posture


@scan_compliance_router.get("/{fw}")
async def get_scan_compliance(
    org_id: UUID,
    scan_id: UUID,
    fw: str,
    identity: AuthIdentity = Depends(require_org_membership()),
    db: AsyncSession = Depends(get_db),
    redis: redis_asyncio.Redis = Depends(get_redis),
) -> dict:
    await require_feature(db, redis, org_id, "compliance.frameworks", member=fw)  # M12 slice 2
    await _load_terminal_scan(db, org_id, scan_id)  # 404 cross-tenant / 409 non-terminal
    try:
        return await compute_scan_posture(db=db, scan_id=scan_id, framework_slug=fw)
    except FrameworkNotFoundError:
        raise HTTPException(status_code=404, detail="unknown_framework") from None
