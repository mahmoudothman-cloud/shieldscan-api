"""On-prem agents: enrolment, authentication, heartbeat, job bridge (M14).

The gateway is a pass-through between an agent and the Redis primitives
the cloud worker already uses (On-Prem Agent Design v1.0 §3):

* jobs — the orchestrator LPUSHes agent-bound jobs onto
  ``shieldscan:agent:<agent_id>:queue`` instead of the shared priority
  lists; ``pop_job`` BRPOPs it for the agent's long-poll;
* progress — events the agent posts are XADDed verbatim to
  ``shieldscan:progress:<scan_id>`` (same ``{"event": json}`` field the
  worker writes, same MAXLEN), so the SSE endpoint cannot tell;
* completions — the agent's ``JobCompletedEvent`` / attack-surface
  event is PUBLISHed verbatim to ``shieldscan:completions`` after the
  org id is pinned to the agent's org;
* cancel — the worker learns of a cancel over Pub/Sub; an agent learns
  it from the heartbeat / poll reply (``cancel_scan_ids``), read from
  the scans table.

Authentication: ``Authorization: Bearer ss_agent_<token>`` → SHA-256 →
``agents.key_hash`` (credential-indexed, ADR-012 amendment); the tenant
context is then set from the row. A revoked agent is 401.
"""

from __future__ import annotations

import hashlib
import json
import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Final
from uuid import UUID

from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.agents import Agent, AgentStatus
from app.models.scans import Scan, ScanJob, ScanStatus

logger = logging.getLogger(__name__)

AGENT_QUEUE_PREFIX: Final[str] = "shieldscan:agent:"
_PROGRESS_KEY_PREFIX: Final[str] = "shieldscan:progress:"
_PROGRESS_MAXLEN: Final[int] = 1000
_COMPLETIONS_CHANNEL: Final[str] = "shieldscan:completions"
_REQUEUE_PREFIX: Final[str] = "shieldscan:agent-requeue:"

ENROL_TOKEN_TTL = timedelta(hours=24)
# Jobs that have not reported within this long after lease are re-queued once, then failed.
JOB_LEASE = timedelta(minutes=35)
_IN_FLIGHT = ("queued", "running")


def _sha(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def agent_queue_key(agent_id: UUID) -> str:
    return f"{AGENT_QUEUE_PREFIX}{agent_id}:queue"


def is_offline(agent: Agent, now: datetime | None = None) -> bool:
    now = now or datetime.now(timezone.utc)
    return (
        agent.last_seen_at is None
        or (now - agent.last_seen_at).total_seconds() > settings.AGENT_OFFLINE_AFTER_S
    )


# ------------------------------------------------------------------ enrolment


def mint_enrolment_token() -> tuple[str, str]:
    """(plaintext, sha256). Shown once in the dashboard."""
    plain = "ss_enrol_" + secrets.token_urlsafe(24)
    return plain, _sha(plain)


def mint_agent_key() -> tuple[str, str, str]:
    """(plaintext, sha256, display prefix)."""
    plain = "ss_agent_" + secrets.token_urlsafe(32)
    return plain, _sha(plain), plain[:14]


async def enrol(
    db: AsyncSession, *, token: str, version: str | None, hostname: str | None, platform: str | None
) -> tuple[Agent, str] | None:
    """Exchange a one-time enrolment token for an agent key. None when the
    token is unknown, expired or already used. Flushes; caller commits.
    Runs before any tenant context (agents is credential-indexed)."""
    row = (
        await db.execute(
            select(Agent).where(
                Agent.enrolment_token_hash == _sha(token), Agent.status == AgentStatus.PENDING
            )
        )
    ).scalar_one_or_none()
    now = datetime.now(timezone.utc)
    if row is None or row.enrolment_expires_at is None or row.enrolment_expires_at < now:
        return None
    plain, key_hash, prefix = mint_agent_key()
    row.key_hash = key_hash
    row.key_prefix = prefix
    row.enrolment_token_hash = None
    row.enrolment_expires_at = None
    row.status = AgentStatus.ACTIVE
    row.enrolled_at = now
    row.last_seen_at = now
    row.version = version
    row.hostname = hostname
    row.platform = platform
    await db.flush()
    return row, plain


async def authenticate(db: AsyncSession, plaintext: str) -> Agent | None:
    """Active agent for a bearer key, or None. No tenant context needed."""
    if not plaintext.startswith("ss_agent_"):
        return None
    row = (
        await db.execute(select(Agent).where(Agent.key_hash == _sha(plaintext)))
    ).scalar_one_or_none()
    if row is None or row.status != AgentStatus.ACTIVE or row.revoked_at is not None:
        return None
    return row


# ------------------------------------------------------------------ heartbeat / cancel


async def heartbeat(
    db: AsyncSession,
    agent: Agent,
    *,
    version: str | None,
    hostname: str | None,
    platform: str | None,
    tools: dict[str, Any] | None,
) -> None:
    agent.last_seen_at = datetime.now(timezone.utc)
    if version:
        agent.version = version
    if hostname:
        agent.hostname = hostname
    if platform:
        agent.platform = platform
    if tools is not None:
        agent.tools = tools
    await db.flush()


async def pending_cancels(db: AsyncSession, agent: Agent) -> list[str]:
    """Scan ids with in-flight jobs on this agent whose scan was canceled."""
    rows = (
        await db.execute(
            select(Scan.id)
            .join(ScanJob, ScanJob.scan_id == Scan.id)
            .where(
                ScanJob.agent_id == agent.id,
                ScanJob.status.in_(_IN_FLIGHT),
                Scan.status == ScanStatus.CANCELED,
            )
            .distinct()
        )
    ).scalars()
    return [str(r) for r in rows]


# ------------------------------------------------------------------ jobs


async def pop_job(redis: Redis, agent: Agent, *, wait_s: int) -> dict[str, Any] | None:
    """BRPOP the agent's queue for up to ``wait_s`` (≤30) seconds; None when
    nothing arrived. ``wait_s == 0`` is a plain RPOP — BRPOP's 0 means
    "block forever", which no HTTP request may do."""
    key = agent_queue_key(agent.id)
    wait_s = max(0, min(wait_s, 30))
    if wait_s == 0:
        raw = await redis.rpop(key)  # type: ignore[misc]
    else:
        result = await redis.brpop([key], timeout=wait_s)  # type: ignore[misc]
        raw = None if result is None else result[1]
    if raw is None:
        return None
    payload: dict[str, Any] = json.loads(raw)
    return payload


async def lease(db: AsyncSession, agent: Agent, job_id: UUID) -> ScanJob | None:
    job = await db.get(ScanJob, job_id)
    if job is None or job.agent_id != agent.id:
        return None
    job.leased_at = datetime.now(timezone.utc)
    if job.status == "queued":
        job.status = "running"
    await db.flush()
    return job


async def job_for_agent(db: AsyncSession, agent: Agent, job_id: UUID) -> ScanJob | None:
    job = await db.get(ScanJob, job_id)
    if job is None or job.agent_id != agent.id:
        return None
    return job


async def push_progress(redis: Redis, scan_id: UUID, events: list[dict[str, Any]]) -> int:
    """XADD each event verbatim (the worker's wire shape). Returns count."""
    key = f"{_PROGRESS_KEY_PREFIX}{scan_id}"
    n = 0
    for ev in events:
        ev = dict(ev)
        ev["scan_id"] = str(scan_id)
        ev.setdefault("timestamp", datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"))
        await redis.xadd(key, {"event": json.dumps(ev)}, maxlen=_PROGRESS_MAXLEN, approximate=True)
        n += 1
    return n


async def publish_completion(
    redis: Redis, agent: Agent, job: ScanJob, event: dict[str, Any]
) -> None:
    """PUBLISH the agent's completion event with the identity fields pinned
    to what the gateway knows (org, scan, job, engine) — an agent cannot
    complete another org's job whatever its payload says."""
    ev = dict(event)
    ev["organization_id"] = str(agent.organization_id)
    ev["scan_id"] = str(job.scan_id)
    if ev.get("event_type") != "attack_surface":
        ev["job_id"] = str(job.id)
        ev["engine"] = job.engine
        ev.setdefault("event_type", "job_completed")
        ev.setdefault("event_seq", {"index": 1, "total": 1})
    ev.setdefault("timestamp", datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"))
    await redis.publish(_COMPLETIONS_CHANNEL, json.dumps(ev))


def failure_event(agent: Agent, job: ScanJob, message: str) -> dict[str, Any]:
    return {
        "event_type": "job_completed",
        "job_id": str(job.id),
        "scan_id": str(job.scan_id),
        "organization_id": str(agent.organization_id),
        "engine": job.engine,
        "status": "failed",
        "error_message": message[:500],
        "event_seq": {"index": 1, "total": 1},
    }


# ------------------------------------------------------------------ lease sweep


async def sweep_leases(
    db: AsyncSession,
    redis: Redis,
    agent: Agent,
    *,
    payloads_by_job: dict[UUID, dict[str, Any]] | None = None,
) -> list[str]:
    """Jobs leased to this agent that did not report inside JOB_LEASE: the
    first time, re-queue the original payload (kept under
    ``shieldscan:agent-requeue:<job_id>``); the second time, fail the job
    through the normal completion path. Returns the job ids acted on."""
    cutoff = datetime.now(timezone.utc) - JOB_LEASE
    stale = list(
        (
            await db.execute(
                select(ScanJob).where(
                    ScanJob.agent_id == agent.id,
                    ScanJob.status.in_(_IN_FLIGHT),
                    ScanJob.leased_at.is_not(None),
                    ScanJob.leased_at < cutoff,
                )
            )
        ).scalars()
    )
    acted: list[str] = []
    for job in stale:
        marker = f"{_REQUEUE_PREFIX}{job.id}"
        raw = await redis.get(marker)
        if raw:
            await publish_completion(
                redis, agent, job, failure_event(agent, job, "agent lease expired twice")
            )
            await redis.delete(marker)
            job.leased_at = None
            acted.append(str(job.id))
            continue
        payload = (payloads_by_job or {}).get(job.id) or await redis.get(
            f"{_REQUEUE_PREFIX}payload:{job.id}"
        )
        if payload:
            data = payload if isinstance(payload, str) else json.dumps(payload)
            await redis.lpush(agent_queue_key(agent.id), data)  # type: ignore[misc]
            await redis.set(marker, "1", ex=int(JOB_LEASE.total_seconds()) * 2)
            job.leased_at = None
            job.status = "queued"
            acted.append(str(job.id))
    await db.flush()
    return acted


async def remember_payload(redis: Redis, job_id: UUID, payload: dict[str, Any]) -> None:
    """Keep the dispatched payload so a lost lease can be re-queued."""
    await redis.set(
        f"{_REQUEUE_PREFIX}payload:{job_id}",
        json.dumps(payload),
        ex=int(JOB_LEASE.total_seconds()) * 3,
    )
