"""M9.0 end-to-end no-op smoke test (ADR-029 Q11 C.c-lite; Stage 3 C3.4).

Exercises the architectural pipes end-to-end with zero real AI calls:
completions_consumer (all jobs terminal) → orchestrator.dispatch_ai_pipeline
(ANALYZING + LPUSH + SCAN_DISPATCHED_AI_PIPELINE) → AIPipelineConsumer (BRPOP →
no-op pipeline) → consumer-driven terminal transition (COMPLETED/PARTIAL +
SCAN_COMPLETED). Also pins the DQ3 empty-findings fast-path (no AI dispatch) and
the DQ1 raw_findings-gating (dispatch fires even when a job failed).

Co-located here (tests/integration created this commit) per the V-BBF / V-KKC
contingency — the project had no integration dir before M9.0.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from uuid import uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.sql import text

from app.models.audit import AuditLog
from app.models.identity import Membership, MembershipRole, Organization, User
from app.models.projects import Project
from app.models.raw_findings import EngineCategory, RawFinding, Severity
from app.models.scans import Scan, ScanJob, ScanStatus, ScanType
from app.services.ai_pipeline_consumer import AIPipelineConsumer
from app.services.audit import ScanAction
from app.services.auth import hash_password
from app.services.completions_consumer import CompletionsConsumer
from tests.conftest import use_org


async def _seed(db_session, *, job_statuses, with_findings):
    org = Organization(name="Smoke Org", slug=f"smk-{uuid4().hex[:8]}")
    db_session.add(org)
    await db_session.flush()
    await use_org(db_session, org.id)
    user = User(
        email=f"smk-{uuid4().hex[:6]}@t.co",
        hashed_password=hash_password("SmkPass-1"),
        full_name="Smk",
        email_verified=True,
    )
    db_session.add(user)
    await db_session.flush()
    db_session.add(
        Membership(user_id=user.id, organization_id=org.id, role=MembershipRole.ADMIN)
    )
    project = Project(
        organization_id=org.id,
        name="SmkApp",
        target_url="https://smk.example.com",
        root_domain="example.com",
        domain_verified=True,
    )
    db_session.add(project)
    await db_session.flush()
    scan = Scan(
        organization_id=org.id,
        project_id=project.id,
        scan_type=ScanType.FULL_WEB,
        status=ScanStatus.RUNNING,
        priority="normal",
        config={},
    )
    db_session.add(scan)
    await db_session.flush()
    jobs = []
    for i, _st in enumerate(job_statuses):
        job = ScanJob(
            organization_id=org.id,
            scan_id=scan.id,
            engine=f"tool{i}",
            target_url="https://smk.example.com",
            status="running",
            idempotency_key=f"{scan.id}:tool{i}:1",
        )
        db_session.add(job)
        jobs.append(job)
    if with_findings:
        db_session.add(
            RawFinding(
                organization_id=org.id,
                scan_id=scan.id,
                tool_name="nuclei",
                engine_category=EngineCategory.DAST,
                title="XSS",
                severity=Severity.HIGH,
                finding_type="xss",
                fingerprint="f" * 64,
                discovered_at=datetime.now(timezone.utc),
            )
        )
    await db_session.commit()
    return org, scan, jobs


def _completion_event(job, org_id, status="completed"):
    return {
        "event_type": "job_completed",
        "job_id": str(job.id),
        "scan_id": str(job.scan_id),
        "organization_id": str(org_id),
        "engine": job.engine,
        "status": status,
        "finding_count": 1,
        "duration_ms": 100,
        "idempotency_key": job.idempotency_key,
        "timestamp": "2026-06-13T12:00:00Z",
    }


async def _scan_status(session_factory, org_id, scan_id):
    async with session_factory() as fresh:
        await fresh.execute(text(f"SET app.current_org_id = '{org_id}'"))
        return (
            await fresh.execute(select(Scan).where(Scan.id == scan_id))
        ).scalar_one().status


async def _audit_actions(session_factory, org_id, scan_id):
    async with session_factory() as fresh:
        await fresh.execute(text(f"SET app.current_org_id = '{org_id}'"))
        rows = (
            await fresh.execute(
                select(AuditLog.action).where(AuditLog.resource_id == scan_id)
            )
        ).scalars().all()
    return set(rows)


@pytest.mark.asyncio
async def test_m9_smoke_completions_to_completed_via_ai_pipeline(
    db_session, fake_redis, session_factory
):
    """Full happy path: terminal jobs + findings → ANALYZING dispatch → consumer
    → COMPLETED, with both SCAN_DISPATCHED_AI_PIPELINE and SCAN_COMPLETED."""
    org, scan, jobs = await _seed(
        db_session, job_statuses=("completed", "completed"), with_findings=True
    )
    completions = CompletionsConsumer(session_factory=session_factory, redis=fake_redis)
    for job in jobs:
        await completions._handle(_completion_event(job, org.id))

    # Phase boundary: scan is ANALYZING + dispatch audit + a queued message.
    assert await _scan_status(session_factory, org.id, scan.id) == ScanStatus.ANALYZING
    assert ScanAction.SCAN_DISPATCHED_AI_PIPELINE.value in await _audit_actions(
        session_factory, org.id, scan.id
    )

    msg = await fake_redis.brpop(AIPipelineConsumer.QUEUE, timeout=1)
    assert msg is not None
    payload = json.loads(msg[1])
    assert payload["scan_id"] == str(scan.id)

    # Consumer drains → no-op → COMPLETED + SCAN_COMPLETED.
    ai_consumer = AIPipelineConsumer(session_factory=session_factory, redis=fake_redis)
    await ai_consumer._process(payload)

    assert await _scan_status(session_factory, org.id, scan.id) == ScanStatus.COMPLETED
    actions = await _audit_actions(session_factory, org.id, scan.id)
    assert ScanAction.SCAN_COMPLETED.value in actions


@pytest.mark.asyncio
async def test_m9_smoke_empty_findings_fast_path(
    db_session, fake_redis, session_factory
):
    """DQ3: no raw_findings → inline COMPLETED, no AI dispatch, empty queue."""
    org, scan, jobs = await _seed(
        db_session, job_statuses=("completed",), with_findings=False
    )
    completions = CompletionsConsumer(session_factory=session_factory, redis=fake_redis)
    for job in jobs:
        await completions._handle(_completion_event(job, org.id))

    assert await _scan_status(session_factory, org.id, scan.id) == ScanStatus.COMPLETED
    actions = await _audit_actions(session_factory, org.id, scan.id)
    assert ScanAction.SCAN_COMPLETED.value in actions
    assert ScanAction.SCAN_DISPATCHED_AI_PIPELINE.value not in actions
    # Nothing enqueued.
    assert await fake_redis.brpop(AIPipelineConsumer.QUEUE, timeout=1) is None


@pytest.mark.asyncio
async def test_m9_smoke_partial_scan_still_dispatches(
    db_session, fake_redis, session_factory
):
    """DQ1: dispatch fires whenever raw_findings exist (even with a failed job);
    consumer finalizes PARTIAL."""
    org, scan, jobs = await _seed(
        db_session, job_statuses=("completed", "failed"), with_findings=True
    )
    completions = CompletionsConsumer(session_factory=session_factory, redis=fake_redis)
    await completions._handle(_completion_event(jobs[0], org.id, status="completed"))
    await completions._handle(_completion_event(jobs[1], org.id, status="failed"))

    assert await _scan_status(session_factory, org.id, scan.id) == ScanStatus.ANALYZING
    msg = await fake_redis.brpop(AIPipelineConsumer.QUEUE, timeout=1)
    assert msg is not None

    ai_consumer = AIPipelineConsumer(session_factory=session_factory, redis=fake_redis)
    await ai_consumer._process(json.loads(msg[1]))

    assert await _scan_status(session_factory, org.id, scan.id) == ScanStatus.PARTIAL
