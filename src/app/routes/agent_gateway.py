"""Agent gateway — what the on-prem binary talks to (M14; design §3–§4).

All routes except ``/enroll`` authenticate with the agent key
(``require_agent``), which also sets the tenant context. Payloads are the
engine's own wire shapes (``events.JobDispatch`` out, ``ProgressEvent`` /
``JobCompletedEvent`` in), bridged verbatim to Redis.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from uuid import UUID

import redis.asyncio as redis_asyncio
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.tenant_context import set_tenant_context
from app.dependencies import get_db, get_rate_limiter, get_real_ip, require_agent
from app.models.agents import Agent
from app.redis_client import get_redis
from app.schemas.agents import (
    EnrolRequest,
    EnrolResponse,
    HeartbeatRequest,
    HeartbeatResponse,
    JobEventsRequest,
    JobFailRequest,
)
from app.services import agents as svc
from app.services.audit import AgentAction, audit
from app.services.rate_limiter import RateLimiter

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/agent", tags=["agent-gateway"])


@router.post("/enroll", response_model=EnrolResponse, status_code=status.HTTP_201_CREATED)
async def enroll(
    body: EnrolRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    limiter: RateLimiter = Depends(get_rate_limiter),
) -> EnrolResponse:
    """One-time token → agent key. Unauthenticated, so rate-limited per IP
    (10/hour); a wrong token is 401 with no detail about why."""
    ip = get_real_ip(request) or "unknown"
    verdict = await limiter.check("agent_enroll", ip, limit=10, window_seconds=3600)
    if not verdict.allowed:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="rate_limited")
    result = await svc.enrol(
        db, token=body.token, version=body.version, hostname=body.hostname, platform=body.platform
    )
    if result is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="enrolment_token_invalid"
        )
    agent, plain = result
    await set_tenant_context(db, agent.organization_id)
    await audit(
        db,
        organization_id=agent.organization_id,
        actor_id=None,
        action=AgentAction.AGENT_ENROLLED,
        resource_type="agent",
        resource_id=agent.id,
        ip_address=ip,
        user_agent=request.headers.get("User-Agent"),
        details={
            "name": agent.name,
            "hostname": body.hostname or "",
            "version": body.version or "",
        },
    )
    await db.commit()
    return EnrolResponse(
        agent_id=agent.id, organization_id=agent.organization_id, name=agent.name, agent_key=plain
    )


@router.post("/heartbeat", response_model=HeartbeatResponse)
async def heartbeat(
    body: HeartbeatRequest,
    agent: Agent = Depends(require_agent),
    db: AsyncSession = Depends(get_db),
    redis: redis_asyncio.Redis = Depends(get_redis),
) -> HeartbeatResponse:
    await svc.heartbeat(
        db,
        agent,
        version=body.version,
        hostname=body.hostname,
        platform=body.platform,
        tools=body.tools,
    )
    requeued = await svc.sweep_leases(db, redis, agent)
    cancels = await svc.pending_cancels(db, agent)
    await db.commit()
    return HeartbeatResponse(
        agent_id=agent.id, name=agent.name, cancel_scan_ids=cancels, requeued_job_ids=requeued
    )


@router.get("/jobs")
async def next_job(
    wait: int = Query(default=25, ge=0, le=30),
    agent: Agent = Depends(require_agent),
    db: AsyncSession = Depends(get_db),
    redis: redis_asyncio.Redis = Depends(get_redis),
) -> Response:
    """Long-poll: one ``JobDispatch`` payload (200) or nothing yet (204).
    Leases the job to this agent before returning it."""
    agent.last_seen_at = datetime.now(timezone.utc)
    payload = await svc.pop_job(redis, agent, wait_s=wait)
    if payload is None:
        await db.commit()
        return Response(status_code=status.HTTP_204_NO_CONTENT)
    try:
        job_id = UUID(str(payload.get("id")))
    except ValueError:
        logger.error("agent %s: queue payload without a job id: %r", agent.id, payload)
        await db.commit()
        return Response(status_code=status.HTTP_204_NO_CONTENT)
    job = await svc.lease(db, agent, job_id)
    if job is None:
        # Not this agent's job any more (unbound / deleted): drop it.
        logger.warning("agent %s: dropped payload for job %s not leased to it", agent.id, job_id)
        await db.commit()
        return Response(status_code=status.HTTP_204_NO_CONTENT)
    await db.commit()
    return Response(content=json.dumps(payload), media_type="application/json")


@router.post("/jobs/{job_id}/events", status_code=status.HTTP_202_ACCEPTED)
async def job_events(
    job_id: UUID,
    body: JobEventsRequest,
    agent: Agent = Depends(require_agent),
    db: AsyncSession = Depends(get_db),
    redis: redis_asyncio.Redis = Depends(get_redis),
) -> dict[str, int]:
    job = await svc.job_for_agent(db, agent, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job_not_found")
    n = await svc.push_progress(redis, job.scan_id, body.events)
    return {"accepted": n}


@router.post("/jobs/{job_id}/complete", status_code=status.HTTP_202_ACCEPTED)
async def job_complete(
    job_id: UUID,
    request: Request,
    agent: Agent = Depends(require_agent),
    db: AsyncSession = Depends(get_db),
    redis: redis_asyncio.Redis = Depends(get_redis),
) -> dict[str, str]:
    """The engine's ``JobCompletedEvent`` (or attack-surface event), as JSON."""
    job = await svc.job_for_agent(db, agent, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job_not_found")
    try:
        event = await request.json()
    except ValueError:
        raise HTTPException(status_code=400, detail="invalid_json")
    if not isinstance(event, dict):
        raise HTTPException(status_code=400, detail="invalid_event")
    await svc.publish_completion(redis, agent, job, event)
    job.leased_at = None
    await db.commit()
    return {"status": "accepted"}


@router.post("/jobs/{job_id}/fail", status_code=status.HTTP_202_ACCEPTED)
async def job_fail(
    job_id: UUID,
    body: JobFailRequest,
    agent: Agent = Depends(require_agent),
    db: AsyncSession = Depends(get_db),
    redis: redis_asyncio.Redis = Depends(get_redis),
) -> dict[str, str]:
    job = await svc.job_for_agent(db, agent, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job_not_found")
    await svc.publish_completion(
        redis, agent, job, svc.failure_event(agent, job, body.error_message)
    )
    job.leased_at = None
    await db.commit()
    return {"status": "accepted"}
