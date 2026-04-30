"""Tests for ``app.services.completions_consumer.CompletionsConsumer``
(Task 4.2).

Six tests pinning the consumer contract:

  9.  Single completion event updates the matching ScanJob.
  10. Aggregate Scan.status = COMPLETED when all jobs terminal-ok +
      audit emits SCAN_COMPLETED exactly once.
  11. Mixed completed + failed jobs → Scan.status = PARTIAL.
  12. Unknown event_type silently ignored.
  13. Handler exception (malformed event, missing fields) does NOT
      kill the loop.
  14a. Per-job completion does NOT emit an audit row — terminal-
       aggregate only (DRIFT-LOG H.2 forcing function).

The consumer's loop subscribes to a global Pub/Sub channel; tests
exercise the extracted ``_handle(event)`` method directly so we
don't depend on pubsub timing in fakeredis (per watch item F).
"""

from __future__ import annotations

import json
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from sqlalchemy import select

from sqlalchemy.ext.asyncio import async_sessionmaker
from app.models.audit import AuditLog
from app.models.identity import Membership, MembershipRole, Organization, User
from app.models.projects import Project
from app.models.scans import Scan, ScanJob, ScanStatus, ScanType
from app.services.auth import hash_password
from app.services.completions_consumer import CompletionsConsumer
from tests.conftest import use_org


@pytest_asyncio.fixture
async def session_factory(db_session):
    """A session factory bound to the SAME engine as the test's
    ``db_session`` fixture. The consumer needs to open fresh sessions
    per event (production: global ``AsyncSessionLocal``); in tests we
    need those sessions on the per-test event loop, not the global
    engine's stale loop. Reuses the test fixture's engine via
    ``db_session.bind.engine``.
    """
    from sqlalchemy.ext.asyncio import AsyncSession as _S
    connection = db_session.bind  # AsyncConnection (test owns lifecycle)

    # Each "factory call" yields a NEW AsyncSession bound to the SAME
    # connection as the test's db_session. Production opens one
    # connection per event from the pool; the test simulates the
    # same semantics on a single shared connection so SET ROLE + SET
    # app.current_org_id + committed visibility all line up.
    class _Factory:
        async def __aenter__(self):
            self._session = _S(bind=connection, expire_on_commit=False)
            return self._session

        async def __aexit__(self, *exc):
            await self._session.close()
            # Don't close the connection — db_session owns it.

    def _factory():
        return _Factory()

    return _factory


@pytest_asyncio.fixture
async def scan_with_jobs(db_session):
    """Persisted Scan + 3 ScanJob rows in `running` state.
    Returns dict with handles tests need."""
    org = Organization(name="C Org", slug=f"cons-{uuid4().hex[:8]}")
    db_session.add(org)
    await db_session.flush()
    await use_org(db_session, org.id)

    user = User(
        email=f"c-{uuid4().hex[:6]}@t.co",
        hashed_password=hash_password("CPass-1"),
        full_name="C",
        email_verified=True,
    )
    db_session.add(user)
    await db_session.flush()
    db_session.add(
        Membership(user_id=user.id, organization_id=org.id, role=MembershipRole.ADMIN)
    )

    project = Project(
        organization_id=org.id,
        name="CApp",
        target_url="https://c.example.com",
        root_domain="example.com",
        domain_verified=True,
    )
    db_session.add(project)
    await db_session.flush()

    scan = Scan(
        organization_id=org.id,
        project_id=project.id,
        scan_type=ScanType.QUICK,
        status=ScanStatus.RUNNING,
        priority="normal",
        config={},
    )
    db_session.add(scan)
    await db_session.flush()

    jobs = [
        ScanJob(
            organization_id=org.id,
            scan_id=scan.id,
            engine=engine,
            target_url="https://c.example.com",
            status="running",
            idempotency_key=f"{scan.id}:{engine}:1234567890",
        )
        for engine in ("subfinder", "httpx", "sslyze")
    ]
    for j in jobs:
        db_session.add(j)
    await db_session.commit()

    return {"org": org, "scan": scan, "jobs": jobs}


def _completion_event(job, status="completed", finding_count=5, duration_ms=1234):
    return {
        "event_type": "job_completed",
        "job_id": str(job.id),
        "scan_id": str(job.scan_id),
        "organization_id": str(job.organization_id),
        "engine": job.engine,
        "status": status,
        "finding_count": finding_count,
        "duration_ms": duration_ms,
        "idempotency_key": job.idempotency_key,
        "timestamp": "2026-04-30T12:00:00Z",
    }


# ---------------------------------------------------------------- 9. single event update


@pytest.mark.asyncio
async def test_consumer_updates_scan_job_on_completion_event(
    scan_with_jobs, fake_redis, db_session, session_factory
):
    s = scan_with_jobs
    job = s["jobs"][0]
    event = _completion_event(job)

    consumer = CompletionsConsumer(
        session_factory=session_factory, redis=fake_redis
    )
    # Direct _handle exercise — no loop, no pubsub. Per watch item F.
    await consumer._handle(event)

    # Re-read the job from a fresh session (consumer used a separate
    # session). Use raw text to bypass any identity-map caching in
    # the test fixture's session.
    async with session_factory() as fresh:
        from sqlalchemy import text as _text
        await fresh.execute(_text(f"SET app.current_org_id = '{s['org'].id}'"))
        result = await fresh.execute(select(ScanJob).where(ScanJob.id == job.id))
        updated = result.scalar_one()
        assert updated.status == "completed"
        assert updated.finding_count == 5
        assert updated.duration_ms == 1234


# ---------------------------------------------------------------- 10. terminal aggregate → COMPLETED


@pytest.mark.asyncio
async def test_consumer_aggregates_scan_status_when_all_jobs_terminal(
    scan_with_jobs, fake_redis, db_session, session_factory
):
    """Workers send events; Python interprets and aggregates.

    REGRESSION GUARD: this test asserts that scan-level status is
    derived from event consumption, not from any external trigger
    (e.g. a Go worker writing the aggregate directly). See ADR-013
    'Anti-patterns this prevents'.
    """
    s = scan_with_jobs
    consumer = CompletionsConsumer(
        session_factory=session_factory, redis=fake_redis
    )

    # Emit completion for each job in turn.
    for job in s["jobs"]:
        await consumer._handle(_completion_event(job))

    async with session_factory() as fresh:
        from sqlalchemy import text as _text
        await fresh.execute(_text(f"SET app.current_org_id = '{s['org'].id}'"))
        scan_row = (
            await fresh.execute(select(Scan).where(Scan.id == s["scan"].id))
        ).scalar_one()
        assert scan_row.status == ScanStatus.COMPLETED

        # Audit: exactly ONE SCAN_COMPLETED row, regardless of how
        # many job_completed events were processed.
        audits = (
            await fresh.execute(
                select(AuditLog).where(AuditLog.action == "scan.completed")
            )
        ).scalars().all()
        assert len(audits) == 1
        assert audits[0].resource_id == s["scan"].id


# ---------------------------------------------------------------- 11. partial


@pytest.mark.asyncio
async def test_consumer_marks_scan_partial_when_some_jobs_failed(
    scan_with_jobs, fake_redis, session_factory
):
    s = scan_with_jobs
    consumer = CompletionsConsumer(
        session_factory=session_factory, redis=fake_redis
    )
    # First two completed, third failed.
    await consumer._handle(_completion_event(s["jobs"][0], status="completed"))
    await consumer._handle(_completion_event(s["jobs"][1], status="completed"))
    await consumer._handle(_completion_event(s["jobs"][2], status="failed"))

    async with session_factory() as fresh:
        from sqlalchemy import text as _text
        await fresh.execute(_text(f"SET app.current_org_id = '{s['org'].id}'"))
        scan_row = (
            await fresh.execute(select(Scan).where(Scan.id == s["scan"].id))
        ).scalar_one()
        assert scan_row.status == ScanStatus.PARTIAL


# ---------------------------------------------------------------- 12. unknown event_type ignored


@pytest.mark.asyncio
async def test_consumer_ignores_unknown_event_types(scan_with_jobs, fake_redis, session_factory):
    s = scan_with_jobs
    job = s["jobs"][0]
    event = _completion_event(job)
    event["event_type"] = "something_else_entirely"

    consumer = CompletionsConsumer(
        session_factory=session_factory, redis=fake_redis
    )
    # Should not raise, should not update.
    await consumer._handle(event)

    async with session_factory() as fresh:
        from sqlalchemy import text as _text
        await fresh.execute(_text(f"SET app.current_org_id = '{s['org'].id}'"))
        result = await fresh.execute(select(ScanJob).where(ScanJob.id == job.id))
        unchanged = result.scalar_one()
        assert unchanged.status == "running"  # unchanged


# ---------------------------------------------------------------- 13. handler exception doesn't kill loop


@pytest.mark.asyncio
async def test_consumer_handler_exception_does_not_kill_loop(
    scan_with_jobs, fake_redis, session_factory
):
    """The loop wraps each ``_handle(event)`` call in a try/except.
    Single-event failure logs and continues. Test the loop-level
    safety, not _handle (which is allowed to raise on malformed input)."""
    consumer = CompletionsConsumer(
        session_factory=session_factory, redis=fake_redis
    )
    # Drive an event missing a required field — _handle raises KeyError.
    bad_event = {"event_type": "job_completed"}  # missing job_id, etc.
    with pytest.raises((KeyError, ValueError)):
        await consumer._handle(bad_event)

    # The loop wrapper protects against this. Simulate one loop-iteration
    # by calling the same wrapping logic the loop uses.
    await consumer._handle_safely(bad_event)
    # No exception raised — the wrapper swallowed it.


# ---------------------------------------------------------------- 14a. per-job audit no-emit (H.2)


@pytest.mark.asyncio
async def test_consumer_does_not_audit_per_job(scan_with_jobs, fake_redis, session_factory):
    """Audit emission policy (DRIFT-LOG H.2): per-job completion is
    captured in scan_jobs.status; only scan-level transitions emit
    audit rows. Pin so a future engineer can't 'helpfully' add a
    SCAN_JOB_COMPLETED audit value + emission and dilute the audit
    log."""
    s = scan_with_jobs
    consumer = CompletionsConsumer(
        session_factory=session_factory, redis=fake_redis
    )
    # First two job completions — non-terminal at scan level.
    await consumer._handle(_completion_event(s["jobs"][0]))
    await consumer._handle(_completion_event(s["jobs"][1]))

    async with session_factory() as fresh:
        from sqlalchemy import text as _text
        await fresh.execute(_text(f"SET app.current_org_id = '{s['org'].id}'"))
        # Zero scan-domain audits at this point.
        scan_audits = (
            await fresh.execute(
                select(AuditLog).where(
                    AuditLog.action.in_(["scan.completed", "scan.failed"])
                )
            )
        ).scalars().all()
        assert scan_audits == [], (
            "per-job completion must NOT emit scan-level audit"
        )

    # Third (final) completion crosses the terminal threshold.
    await consumer._handle(_completion_event(s["jobs"][2]))

    async with session_factory() as fresh:
        from sqlalchemy import text as _text
        await fresh.execute(_text(f"SET app.current_org_id = '{s['org'].id}'"))
        scan_audits = (
            await fresh.execute(
                select(AuditLog).where(
                    AuditLog.action.in_(["scan.completed", "scan.failed"])
                )
            )
        ).scalars().all()
        assert len(scan_audits) == 1
        assert scan_audits[0].action == "scan.completed"


# ---------------------------------------------------------------- 14b. cancel-wins race (Task 4.5)


@pytest.mark.asyncio
async def test_consumer_does_not_overwrite_canceled_scan(
    scan_with_jobs, fake_redis, session_factory
):
    """Cancel-wins regression guard (Task 4.5 H.2 reversal).

    Setup: cancel the scan via direct DB write (simulating the cancel
    endpoint), then drive completion events for the remaining jobs.
    Verify: Scan.status stays CANCELED — completion events do NOT
    overwrite scan-level state. User intent wins at scan-level
    aggregation.

    REGRESSION GUARD: a future "helpful" change that drops CANCELED
    from the consumer's terminal-state short-circuit set would let
    completion events overwrite CANCELED → COMPLETED/PARTIAL. This
    test breaks immediately. See DRIFT-LOG 2026-04-30 Task 4.5
    cancel-wins entry + ADR-013.
    """
    s = scan_with_jobs

    # Cancel the scan at scan-level (simulates the 4.5 cancel endpoint).
    async with session_factory() as fresh:
        from sqlalchemy import text as _text
        await fresh.execute(_text(f"SET app.current_org_id = '{s['org'].id}'"))
        scan_row = (
            await fresh.execute(select(Scan).where(Scan.id == s["scan"].id))
        ).scalar_one()
        scan_row.status = ScanStatus.CANCELED
        await fresh.commit()

    # Now drive completion events for all 3 jobs. The consumer should
    # update job-level rows but NOT overwrite scan-level CANCELED state.
    consumer = CompletionsConsumer(
        session_factory=session_factory, redis=fake_redis
    )
    for job in s["jobs"]:
        await consumer._handle(_completion_event(job))

    async with session_factory() as fresh:
        from sqlalchemy import text as _text
        await fresh.execute(_text(f"SET app.current_org_id = '{s['org'].id}'"))
        final = (
            await fresh.execute(select(Scan).where(Scan.id == s["scan"].id))
        ).scalar_one()
        assert final.status == ScanStatus.CANCELED, (
            f"cancel must win: completion events arriving after a "
            f"scan-level cancel must not overwrite CANCELED state; "
            f"got {final.status!r}"
        )

        # No SCAN_COMPLETED audit should have been emitted.
        scan_audits = (
            await fresh.execute(
                select(AuditLog).where(
                    AuditLog.action.in_(["scan.completed", "scan.failed"])
                )
            )
        ).scalars().all()
        assert scan_audits == [], (
            "consumer must NOT emit scan-level audit when scan is "
            "already terminal (CANCELED in this case)"
        )
