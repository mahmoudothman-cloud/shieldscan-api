"""Recovery of scan jobs whose workers died before reporting them.

The stranding itself is an engine defect (Drift #70) and is fixed there.
What is pinned here is the Python half:

  1. The ghost test. A job is stranded only if it is non-terminal in
     PostgreSQL AND its payload is absent from Redis — from the priority
     queues and from every worker's processing list. Status alone is not
     enough: a job legitimately waiting in the queue reads ``queued`` too,
     and failing one of those would kill live work.
  2. Failing a stranded job goes through the ordinary consumer path, so
     the parent scan aggregates. That aggregation is the point: findings
     the job's SIBLINGS already produced sit unanalysed until it happens,
     so the recovery is of compute already spent, not of a status field.
  3. ``error_message`` is persisted, and is distinct enough to separate a
     stranded job from one a tool genuinely failed.
  4. A terminal job cannot be moved off its status. The reclaimer can
     lose a race with an acknowledgement and publish a failure for a job
     that finished; without this guard that event would overwrite a
     completed job — findings ingested, scan aggregated — with ``failed``.
"""

from __future__ import annotations

import json
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession as _SQLAS

from app.db.tenant_context import TenantSession as _TenantSession
from app.models.identity import Membership, MembershipRole, Organization, User
from app.models.projects import Project
from app.models.scans import Scan, ScanJob, ScanStatus, ScanType
from app.services.auth import hash_password
from app.services.completions_consumer import CompletionsConsumer
from app.services.stranded_jobs import (
    STRANDED_ERROR_MESSAGE,
    fail_stranded_jobs,
    failure_event,
    find_stranded_jobs,
    payload_index,
)
from tests.conftest import use_org

pytestmark = pytest.mark.asyncio


# ---------------------------------------------------------------- fixtures


@pytest_asyncio.fixture
async def session_factory(db_session):
    """Session factory bound to the test's AsyncConnection.

    ``sync_session_class=TenantSession`` mirrors production
    ``AsyncSessionLocal``; a bare AsyncSession would bypass the
    ``after_begin`` tenant re-apply and the tenant guard.
    """
    connection = db_session.bind

    class _Factory:
        async def __aenter__(self):
            self._session = _SQLAS(
                bind=connection,
                sync_session_class=_TenantSession,
                expire_on_commit=False,
            )
            return self._session

        async def __aexit__(self, *exc):
            await self._session.close()

    def _factory():
        return _Factory()

    return _factory


@pytest_asyncio.fixture
async def scan_with_jobs(db_session):
    """A running scan with two jobs: one that finished, one still open.

    This is the shape the stranding actually took — the slowest engine
    was in flight when the worker died and its siblings had already
    completed, so the scan could never aggregate.
    """
    org = Organization(name="Ghost Org", slug=f"ghost-{uuid4().hex[:8]}")
    db_session.add(org)
    await db_session.flush()
    await use_org(db_session, org.id)

    user = User(
        email=f"g-{uuid4().hex[:6]}@t.co",
        hashed_password=hash_password("GPass-1"),
        full_name="G",
        email_verified=True,
    )
    db_session.add(user)
    await db_session.flush()
    db_session.add(
        Membership(user_id=user.id, organization_id=org.id, role=MembershipRole.ADMIN)
    )

    project = Project(
        organization_id=org.id,
        name="GApp",
        target_url="https://g.example.com",
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

    done = ScanJob(
        organization_id=org.id,
        scan_id=scan.id,
        engine="sslyze",
        target_url="https://g.example.com",
        status="completed",
        idempotency_key=f"{scan.id}:sslyze:1234567890",
    )
    stuck = ScanJob(
        organization_id=org.id,
        scan_id=scan.id,
        engine="nuclei",
        target_url="https://g.example.com",
        status="queued",
        idempotency_key=f"{scan.id}:nuclei:1234567890",
    )
    db_session.add_all([done, stuck])
    await db_session.commit()

    return {"org": org, "scan": scan, "done": done, "stuck": stuck}


def _completion_event(job, *, status="completed", error_message=None, duration_ms=10):
    event = {
        "event_type": "job_completed",
        "job_id": str(job.id),
        "scan_id": str(job.scan_id),
        "organization_id": str(job.organization_id),
        "engine": job.engine,
        "status": status,
        "finding_count": 0,
        "duration_ms": duration_ms,
        "idempotency_key": job.idempotency_key,
        "timestamp": "2026-08-19T12:00:00Z",
        "event_seq": {"index": 1, "total": 1},
        "findings": [],
    }
    if error_message is not None:
        event["error_message"] = error_message
    return event


async def _reread(session_factory, fixture, which: str):
    """Re-read a job and its scan from a session the consumer never used.

    The consumer writes through its own session; the fixture's session has
    ``expire_on_commit=False``, so its identity map would hand back the
    pre-write values and every assertion below would pass or fail on stale
    state. Same reason the module's own reads use ``select_fresh``.
    """
    from app.db.tenant_context import set_tenant_context

    async with session_factory() as fresh:
        await set_tenant_context(fresh, fixture["org"].id)
        job = (
            await fresh.execute(
                select(ScanJob).where(ScanJob.id == fixture[which].id)
            )
        ).scalar_one()
        scan = (
            await fresh.execute(select(Scan).where(Scan.id == fixture["scan"].id))
        ).scalar_one()
        return job, scan


def _payload(idempotency_key: str) -> str:
    return json.dumps(
        {
            "id": "job_x",
            "scan_id": "s1",
            "organization_id": "o1",
            "engine": "nuclei",
            "idempotency_key": idempotency_key,
        }
    )


# ---------------------------------------------------------------- payload index


async def test_payload_index_sees_queued_payloads(fake_redis):
    await fake_redis.lpush("shieldscan:queue:high", _payload("k_queued"))

    assert await payload_index(fake_redis) == {"k_queued"}


async def test_payload_index_sees_in_flight_payloads(fake_redis):
    """A job a worker is running right now lives in its processing list.

    Missing this half is the dangerous direction: every actively running
    job would look stranded and be failed underneath a live worker.
    """
    await fake_redis.lpush(
        "shieldscan:processing:host-01-deadbeef:normal", _payload("k_running")
    )

    assert await payload_index(fake_redis) == {"k_running"}


async def test_payload_index_survives_an_undecodable_entry(fake_redis):
    await fake_redis.lpush("shieldscan:queue:high", "not-json{{{")
    await fake_redis.lpush("shieldscan:queue:high", _payload("k_good"))

    assert await payload_index(fake_redis) == {"k_good"}


# ---------------------------------------------------------------- the ghost test


async def test_find_stranded_returns_the_job_with_no_payload(db_session, scan_with_jobs):
    stranded = await find_stranded_jobs(db_session, present=set())

    assert [j.job_id for j in stranded] == [scan_with_jobs["stuck"].id]


async def test_find_stranded_skips_a_job_still_queued_in_redis(
    db_session, scan_with_jobs
):
    """Status alone is not the test.

    A job genuinely waiting its turn is also ``queued``. Acting on status
    alone would fail work that is about to run.
    """
    present = {scan_with_jobs["stuck"].idempotency_key}

    assert await find_stranded_jobs(db_session, present) == []


async def test_find_stranded_ignores_terminal_jobs(db_session, scan_with_jobs):
    stranded = await find_stranded_jobs(db_session, present=set())

    assert scan_with_jobs["done"].id not in [j.job_id for j in stranded]


# ---------------------------------------------------------------- the repair


async def test_failing_a_stranded_job_aggregates_its_parent_scan(
    db_session, session_factory, scan_with_jobs, fake_redis
):
    """The reason the backfill is recovery rather than tidying.

    While one job hangs, ``_maybe_complete_scan`` never fires, so the
    scan never leaves RUNNING and the findings its siblings produced are
    never analysed. Failing the stranded job is what releases that.
    """
    consumer = CompletionsConsumer(session_factory=session_factory, redis=fake_redis)
    stranded = await find_stranded_jobs(db_session, present=set())

    applied = await fail_stranded_jobs(consumer, stranded)
    assert applied == 1

    job, scan = await _reread(session_factory, scan_with_jobs, "stuck")

    assert job.status == "failed"
    assert scan.status == ScanStatus.PARTIAL, (
        "the parent scan is still non-terminal; the stranded job was marked "
        "failed but the aggregation that makes the recovery worth anything "
        "did not happen"
    )


async def test_stranded_failure_is_separable_from_a_tool_failure(
    db_session, session_factory, scan_with_jobs, fake_redis
):
    consumer = CompletionsConsumer(session_factory=session_factory, redis=fake_redis)
    stranded = await find_stranded_jobs(db_session, present=set())
    await fail_stranded_jobs(consumer, stranded)

    job, _ = await _reread(session_factory, scan_with_jobs, "stuck")

    assert job.error_message == STRANDED_ERROR_MESSAGE
    assert "Drift #70" in job.error_message


@pytest.mark.asyncio
async def test_failure_event_takes_the_status_only_consumer_path(scan_with_jobs):
    """``status=failed`` with ``event_seq.total == 1`` routes to the
    status-only handler — no findings, no accumulator."""
    stuck = scan_with_jobs["stuck"]
    event = failure_event(
        type("S", (), {
            "job_id": stuck.id,
            "scan_id": stuck.scan_id,
            "organization_id": stuck.organization_id,
            "engine": stuck.engine,
            "idempotency_key": stuck.idempotency_key,
            "status": "queued",
        })()
    )

    assert event["event_type"] == "job_completed"
    assert event["status"] == "failed"
    assert event["event_seq"] == {"index": 1, "total": 1}
    assert "findings" not in event
    assert event["error_message"] == STRANDED_ERROR_MESSAGE


# ------------------------------------------------- consumer-side guards


async def test_persist_writes_error_message(
    db_session, session_factory, scan_with_jobs, fake_redis
):
    """The column existed from the first migration and was never written.

    Without it the reclaimer's whole diagnostic payload — why a job died
    — survives only in a log line, and a log line is not queryable.
    """
    consumer = CompletionsConsumer(session_factory=session_factory, redis=fake_redis)
    await consumer.apply_event(
        _completion_event(
            scan_with_jobs["stuck"], status="failed", error_message="nuclei exited 1"
        )
    )

    job, _ = await _reread(session_factory, scan_with_jobs, "stuck")
    assert job.error_message == "nuclei exited 1"


async def test_a_terminal_job_is_never_moved_off_its_status(
    db_session, session_factory, scan_with_jobs, fake_redis
):
    """The guard that makes the reclaimer safe by construction.

    A reclaim sweep can publish a failure for a job that had in fact
    completed — the worker died between publishing and acknowledging.
    Letting that event through would overwrite a completed job whose
    findings are already ingested and whose scan has already aggregated.
    """
    consumer = CompletionsConsumer(session_factory=session_factory, redis=fake_redis)

    await consumer.apply_event(
        _completion_event(
            scan_with_jobs["done"], status="failed", error_message="late reclaim"
        )
    )

    job, _ = await _reread(session_factory, scan_with_jobs, "done")
    assert job.status == "completed", (
        "a late failure event downgraded an already-completed job"
    )
    assert job.error_message is None
