"""Tests for the AI pipeline consumer (ADR-029 Q1; M9.0 Stage 3 C3.3).

Exercises the NEW behavior introduced at C2: BRPOP-loop lifecycle, the no-op
pipeline + DQ2 consumer-driven terminal transition, the DQ5 relocated
SCAN_COMPLETED audit, the Q8 fail-path (FAILED + ai_pipeline_degraded), and the
DQ4 idempotency guard (skip non-ANALYZING scans). The consumer is driven via
``_process`` directly (no loop), mirroring the CompletionsConsumer test style.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.sql import text

from app.models.audit import AuditLog
from app.models.identity import Membership, MembershipRole, Organization, User
from app.models.projects import Project
from app.models.scans import Scan, ScanJob, ScanStatus, ScanType
from app.services import ai_pipeline_consumer as consumer_mod
from app.services.ai_pipeline_consumer import AIPipelineConsumer
from app.services.audit import ScanAction
from app.services.auth import hash_password
from tests.conftest import use_org


async def _seed_analyzing_scan(db_session, *, job_statuses=("completed",)):
    """Org + project + a scan already in ANALYZING + sibling jobs."""
    org = Organization(name="AIP Org", slug=f"aip-{uuid4().hex[:8]}")
    db_session.add(org)
    await db_session.flush()
    await use_org(db_session, org.id)
    user = User(
        email=f"aip-{uuid4().hex[:6]}@t.co",
        hashed_password=hash_password("AipPass-1"),
        full_name="AIP",
        email_verified=True,
    )
    db_session.add(user)
    await db_session.flush()
    db_session.add(
        Membership(user_id=user.id, organization_id=org.id, role=MembershipRole.ADMIN)
    )
    project = Project(
        organization_id=org.id,
        name="AIPApp",
        target_url="https://aip.example.com",
        root_domain="example.com",
        domain_verified=True,
    )
    db_session.add(project)
    await db_session.flush()
    scan = Scan(
        organization_id=org.id,
        project_id=project.id,
        scan_type=ScanType.FULL_WEB,
        status=ScanStatus.ANALYZING,
        priority="normal",
        config={},
    )
    db_session.add(scan)
    await db_session.flush()
    for i, st in enumerate(job_statuses):
        db_session.add(
            ScanJob(
                organization_id=org.id,
                scan_id=scan.id,
                engine=f"tool{i}",
                target_url="https://aip.example.com",
                status=st,
                finding_count=3,
                idempotency_key=f"{scan.id}:tool{i}:1",
            )
        )
    await db_session.commit()
    return org, scan


def _payload(org, scan):
    return {"scan_id": str(scan.id), "organization_id": str(org.id)}


async def _read_scan(session_factory, org_id, scan_id):
    async with session_factory() as fresh:
        await fresh.execute(text(f"SET app.current_org_id = '{org_id}'"))
        return (
            await fresh.execute(select(Scan).where(Scan.id == scan_id))
        ).scalar_one()


# ---------------------------------------------------------------- lifecycle


@pytest.mark.asyncio
async def test_consumer_start_is_idempotent(fake_redis, session_factory):
    c = AIPipelineConsumer(session_factory=session_factory, redis=fake_redis)
    await c.start()
    task = c._task
    await c.start()  # second start is a no-op
    assert c._task is task
    await c.stop()


@pytest.mark.asyncio
async def test_consumer_stop_drains(fake_redis, session_factory):
    c = AIPipelineConsumer(session_factory=session_factory, redis=fake_redis)
    await c.start()
    await c.stop()
    assert c._task is None


# ---------------------------------------------------------------- _process happy path


@pytest.mark.asyncio
async def test_consumer_completes_scan_after_no_op(
    db_session, fake_redis, session_factory
):
    org, scan = await _seed_analyzing_scan(db_session, job_statuses=("completed",))
    c = AIPipelineConsumer(session_factory=session_factory, redis=fake_redis)
    await c._process(_payload(org, scan))

    fresh = await _read_scan(session_factory, org.id, scan.id)
    assert fresh.status == ScanStatus.COMPLETED
    assert fresh.ai_pipeline_degraded is False


@pytest.mark.asyncio
async def test_consumer_marks_partial_when_any_job_failed(
    db_session, fake_redis, session_factory
):
    org, scan = await _seed_analyzing_scan(
        db_session, job_statuses=("completed", "failed")
    )
    c = AIPipelineConsumer(session_factory=session_factory, redis=fake_redis)
    await c._process(_payload(org, scan))

    fresh = await _read_scan(session_factory, org.id, scan.id)
    assert fresh.status == ScanStatus.PARTIAL


@pytest.mark.asyncio
async def test_consumer_emits_scan_completed_audit(
    db_session, fake_redis, session_factory
):
    org, scan = await _seed_analyzing_scan(db_session, job_statuses=("completed",))
    c = AIPipelineConsumer(session_factory=session_factory, redis=fake_redis)
    await c._process(_payload(org, scan))

    async with session_factory() as fresh:
        await fresh.execute(text(f"SET app.current_org_id = '{org.id}'"))
        audits = (
            await fresh.execute(
                select(AuditLog).where(
                    AuditLog.resource_id == scan.id,
                    AuditLog.action == ScanAction.SCAN_COMPLETED.value,
                )
            )
        ).scalars().all()
    assert len(audits) == 1


# ---------------------------------------------------------------- Q8 fail path


@pytest.mark.asyncio
async def test_consumer_marks_failed_and_degraded_on_pipeline_error(
    db_session, fake_redis, session_factory, monkeypatch
):
    org, scan = await _seed_analyzing_scan(db_session, job_statuses=("completed",))

    async def _boom(*, db, scan_id):
        raise RuntimeError("pipeline blew up")

    monkeypatch.setattr(consumer_mod, "run", _boom)

    c = AIPipelineConsumer(session_factory=session_factory, redis=fake_redis)
    await c._process(_payload(org, scan))  # _process swallows + routes to _fail_scan

    fresh = await _read_scan(session_factory, org.id, scan.id)
    assert fresh.status == ScanStatus.FAILED
    assert fresh.ai_pipeline_degraded is True


# ---------------------------------------------------------------- DQ4 idempotency


@pytest.mark.asyncio
async def test_consumer_skips_scan_not_in_analyzing(
    db_session, fake_redis, session_factory
):
    org, scan = await _seed_analyzing_scan(db_session, job_statuses=("completed",))
    # Flip to COMPLETED before processing — a re-delivered message must skip.
    async with session_factory() as s:
        await s.execute(text(f"SET app.current_org_id = '{org.id}'"))
        sc = (await s.execute(select(Scan).where(Scan.id == scan.id))).scalar_one()
        sc.status = ScanStatus.COMPLETED
        await s.commit()

    c = AIPipelineConsumer(session_factory=session_factory, redis=fake_redis)
    await c._process(_payload(org, scan))  # no-op (not ANALYZING)

    async with session_factory() as fresh:
        await fresh.execute(text(f"SET app.current_org_id = '{org.id}'"))
        audits = (
            await fresh.execute(
                select(AuditLog).where(
                    AuditLog.resource_id == scan.id,
                    AuditLog.action == ScanAction.SCAN_COMPLETED.value,
                )
            )
        ).scalars().all()
    # No SCAN_COMPLETED emitted by the consumer for an already-terminal scan.
    assert audits == []
