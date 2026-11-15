"""Tool-health endpoint (M10.D; Task 10.6; SPEC §6 line 567).

One org-scoped GET: ``GET /orgs/{org_id}/tools/health`` — the customer/ops
view of the engine worker fleet's per-tool availability, read from the
``shieldscan:workers:*`` heartbeat keys.

Tenancy via ``require_org_membership()``. The worker fleet is GLOBAL
infrastructure (workers serve all tenants), so org-scoping here is
auth-gating, not data-partitioning — the same global-behind-org-path shape
as the M10.C compliance reference data. Ungated (tier-enforcement
forward-pinned to billing, per the M10.A /fix + M10.B reports + M10.C
compliance precedent). No audit rows — a GET (V-JJH).

Distinct from ``/ready`` (main.py): that probe checks the API pod's OWN
deps (postgres + redis) for k8s readiness; this reports the worker fleet.
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import AuthIdentity, get_db, require_org_membership
from app.models.agents import Agent, AgentStatus
from app.models.scans import ScanJob
from app.redis_client import get_redis
from app.services import agents as agent_svc
from app.services.tool_health import gather_tool_health

router = APIRouter(prefix="/orgs/{org_id}/tools", tags=["tools"])


@router.get("/health")
async def get_tool_health(
    org_id: UUID,
    identity: AuthIdentity = Depends(require_org_membership()),
    redis=Depends(get_redis),
    db: AsyncSession = Depends(get_db),
) -> dict:
    # Ungated at M10.D; tier-enforcement forward-pinned to billing (4th
    # instance after M10.A /fix + M10.B reports + M10.C compliance).
    health = await gather_tool_health(redis)
    # M14: the org's own on-prem agents beside the global fleet — which
    # engines each one can run (from its last heartbeat) and what it has
    # in flight. ``agents`` is credential-indexed, so filter the org here.
    health["agents"] = await _agent_health(db, org_id)
    return health


async def _agent_health(db: AsyncSession, org_id) -> list[dict]:
    rows = list(
        (
            await db.execute(
                select(Agent)
                .where(Agent.organization_id == org_id, Agent.status != AgentStatus.REVOKED)
                .order_by(Agent.created_at)
            )
        ).scalars()
    )
    if not rows:
        return []
    in_flight = dict(
        (
            await db.execute(
                select(ScanJob.agent_id, func.count(ScanJob.id))
                .where(
                    ScanJob.agent_id.in_([a.id for a in rows]),
                    ScanJob.status.in_(("queued", "running")),
                )
                .group_by(ScanJob.agent_id)
            )
        ).all()
    )
    out = []
    for a in rows:
        status = a.status.value
        if a.status == AgentStatus.ACTIVE and agent_svc.is_offline(a):
            status = "offline"
        tools = a.tools or {}
        out.append(
            {
                "id": str(a.id),
                "name": a.name,
                "status": status,
                "version": a.version,
                "hostname": a.hostname,
                "last_seen_at": a.last_seen_at.isoformat() if a.last_seen_at else None,
                "engines": sorted(k for k, v in tools.items() if (v or {}).get("status") == "ok"),
                "missing": sorted(k for k, v in tools.items() if (v or {}).get("status") != "ok"),
                "in_flight_jobs": int(in_flight.get(a.id, 0)),
            }
        )
    return out
