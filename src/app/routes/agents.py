"""Org-facing agent management (M14): create (mints the one-time enrolment
token), list, revoke. Admin role, JWT only. ``agents`` is credential-indexed
(no RLS), so every query here filters on ``organization_id`` explicitly."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

import redis.asyncio as redis_asyncio
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.dependencies import AuthIdentity, get_db, get_real_ip, require_org_membership
from app.models.agents import Agent, AgentStatus
from app.models.identity import MembershipRole
from app.models.projects import Project
from app.redis_client import get_redis
from app.schemas.agents import (
    AgentCreatedResponse,
    AgentCreateRequest,
    AgentListResponse,
    AgentResponse,
)
from app.services import agents as svc
from app.services.audit import AgentAction, audit
from app.services.plan_enforcement import require_capacity
from app.services.plans import invalidate_limits

router = APIRouter(prefix="/orgs/{org_id}/agents", tags=["agents"])


async def _require_admin(
    identity: AuthIdentity = Depends(require_org_membership(jwt_only=True)),
) -> AuthIdentity:
    if identity.role != MembershipRole.ADMIN:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="insufficient_role")
    return identity


def _view(agent: Agent, project_count: int) -> AgentResponse:
    status_value = agent.status.value
    if agent.status == AgentStatus.ACTIVE and svc.is_offline(agent):
        status_value = "offline"
    return AgentResponse(
        id=agent.id,
        name=agent.name,
        description=agent.description,
        status=status_value,
        key_prefix=agent.key_prefix,
        enrolled_at=agent.enrolled_at,
        last_seen_at=agent.last_seen_at,
        version=agent.version,
        hostname=agent.hostname,
        platform=agent.platform,
        tools=agent.tools or {},
        project_count=project_count,
        created_at=agent.created_at,
    )


async def _project_counts(db: AsyncSession, org_id: UUID) -> dict[UUID, int]:
    rows = (
        await db.execute(
            select(Project.agent_id, func.count(Project.id))
            .where(
                Project.organization_id == org_id,
                Project.agent_id.is_not(None),
                Project.archived_at.is_(None),
            )
            .group_by(Project.agent_id)
        )
    ).all()
    return {aid: int(n) for aid, n in rows}


@router.get("", response_model=AgentListResponse)
async def list_agents(
    org_id: UUID,
    identity: AuthIdentity = Depends(require_org_membership()),
    db: AsyncSession = Depends(get_db),
) -> AgentListResponse:
    agents = list(
        (
            await db.execute(
                select(Agent)
                .where(Agent.organization_id == org_id)
                .order_by(Agent.created_at.desc())
            )
        ).scalars()
    )
    counts = await _project_counts(db, org_id)
    return AgentListResponse(agents=[_view(a, counts.get(a.id, 0)) for a in agents])


@router.post("", response_model=AgentCreatedResponse, status_code=status.HTTP_201_CREATED)
async def create_agent(
    org_id: UUID,
    body: AgentCreateRequest,
    request: Request,
    identity: AuthIdentity = Depends(_require_admin),
    db: AsyncSession = Depends(get_db),
    redis: redis_asyncio.Redis = Depends(get_redis),
) -> AgentCreatedResponse:
    active = int(
        (
            await db.execute(
                select(func.count(Agent.id)).where(
                    Agent.organization_id == org_id, Agent.status != AgentStatus.REVOKED
                )
            )
        ).scalar_one()
    )
    await require_capacity(db, redis, org_id, "agents.max", active)
    token, token_hash = svc.mint_enrolment_token()
    expires = datetime.now(timezone.utc) + svc.ENROL_TOKEN_TTL
    agent = Agent(
        organization_id=org_id,
        name=body.name,
        description=body.description,
        status=AgentStatus.PENDING,
        enrolment_token_hash=token_hash,
        enrolment_expires_at=expires,
        created_by=identity.user.id if identity.user is not None else None,
    )
    db.add(agent)
    await db.flush()
    await audit(
        db,
        organization_id=org_id,
        actor_id=identity.user.id if identity.user is not None else None,
        action=AgentAction.AGENT_CREATED,
        resource_type="agent",
        resource_id=agent.id,
        ip_address=get_real_ip(request),
        user_agent=request.headers.get("User-Agent"),
        details={"name": agent.name},
    )
    await db.commit()
    await db.refresh(agent)
    base = settings.APP_BASE_URL.rstrip("/")
    return AgentCreatedResponse(
        agent=_view(agent, 0),
        enrolment_token=token,
        enrolment_expires_at=expires,
        enrol_command=f"shieldscan-agent enroll --api {base} --token {token}",
    )


@router.delete("/{agent_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_agent(
    org_id: UUID,
    agent_id: UUID,
    request: Request,
    identity: AuthIdentity = Depends(_require_admin),
    db: AsyncSession = Depends(get_db),
    redis: redis_asyncio.Redis = Depends(get_redis),
) -> Response:
    """Revoke: the key stops working at once, bound projects are unbound
    (their next scan would otherwise fail with agent_offline forever)."""
    agent = (
        await db.execute(select(Agent).where(Agent.id == agent_id, Agent.organization_id == org_id))
    ).scalar_one_or_none()
    if agent is None:
        raise HTTPException(status_code=404, detail="agent_not_found")
    now = datetime.now(timezone.utc)
    agent.status = AgentStatus.REVOKED
    agent.revoked_at = now
    agent.enrolment_token_hash = None
    projects = list(
        (
            await db.execute(
                select(Project).where(
                    Project.organization_id == org_id, Project.agent_id == agent.id
                )
            )
        ).scalars()
    )
    for p in projects:
        p.agent_id = None
    await audit(
        db,
        organization_id=org_id,
        actor_id=identity.user.id if identity.user is not None else None,
        action=AgentAction.AGENT_REVOKED,
        resource_type="agent",
        resource_id=agent.id,
        ip_address=get_real_ip(request),
        user_agent=request.headers.get("User-Agent"),
        details={"name": agent.name},
    )
    await db.commit()
    await invalidate_limits(redis, org_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
