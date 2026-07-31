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

from app.dependencies import AuthIdentity, require_org_membership
from app.redis_client import get_redis
from app.services.tool_health import gather_tool_health

router = APIRouter(prefix="/orgs/{org_id}/tools", tags=["tools"])


@router.get("/health")
async def get_tool_health(
    org_id: UUID,
    identity: AuthIdentity = Depends(require_org_membership()),
    redis=Depends(get_redis),
) -> dict:
    # Ungated at M10.D; tier-enforcement forward-pinned to billing (4th
    # instance after M10.A /fix + M10.B reports + M10.C compliance).
    return await gather_tool_health(redis)
