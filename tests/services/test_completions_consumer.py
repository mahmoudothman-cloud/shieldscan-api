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


# ============================================================
# Task 8.3α — EventAttackSurface UPSERT handler (7 tests)
# ============================================================
#
# These tests pin the _handle_attack_surface contract per Task 8.3α
# design doc 0030319 §3.5 + plan dba6a7c §3.5 + Drift #58 Layer B
# repair. Stage 3 Commit 3 of 3 (cross-repo trio with shieldscan-docs
# 721ba02 + shieldscan-engine fc75a98).
#
# Pattern: fakeredis + direct _handle invocation (per watch item F);
# fresh-session reads with explicit SET app.current_org_id to verify
# UPSERTed rows.


def _attack_surface_event(
    scan,
    org,
    root_domain="c.example.com",
    subdomains=None,
):
    if subdomains is None:
        subdomains = [
            {
                "url": "https://api.c.example.com",
                "status": "live",
                "status_code": 200,
                "tech_stack": ["nginx", "Node.js"],
                "last_probed_at": "2026-05-30T14:32:00Z",
            },
            {
                "url": "https://staging.c.example.com",
                "status": "live",
                "status_code": 301,
                "tech_stack": ["nginx"],
                "last_probed_at": "2026-05-30T14:32:00Z",
            },
        ]
    return {
        "event_type": "attack_surface",
        "scan_id": str(scan.id),
        "organization_id": str(org.id),
        "root_domain": root_domain,
        "subdomains": subdomains,
        "timestamp": "2026-05-30T14:32:01Z",
    }


# ---------------------------------------------------------------- 8.3α.1 happy-path UPSERT inserts


@pytest.mark.asyncio
async def test_handle_attack_surface_inserts_subdomains(
    scan_with_jobs, fake_redis, session_factory
):
    from app.models.recon import AttackSurface, SubdomainStatus

    s = scan_with_jobs
    event = _attack_surface_event(s["scan"], s["org"])

    consumer = CompletionsConsumer(
        session_factory=session_factory, redis=fake_redis
    )
    await consumer._handle(event)

    async with session_factory() as fresh:
        from sqlalchemy import text as _text
        await fresh.execute(_text(f"SET app.current_org_id = '{s['org'].id}'"))
        rows = (
            await fresh.execute(
                select(AttackSurface).where(AttackSurface.scan_id == s["scan"].id)
            )
        ).scalars().all()
        assert len(rows) == 2
        urls = {r.full_url for r in rows}
        assert urls == {
            "https://api.c.example.com",
            "https://staging.c.example.com",
        }
        labels = {r.subdomain for r in rows}
        assert labels == {"api.c.example.com", "staging.c.example.com"}
        statuses = {r.status for r in rows}
        assert statuses == {SubdomainStatus.LIVE}


# ---------------------------------------------------------------- 8.3α.2 duplicate-event idempotency (UPSERT)


@pytest.mark.asyncio
async def test_handle_attack_surface_upserts_on_conflict(
    scan_with_jobs, fake_redis, session_factory
):
    """Re-delivering the same event MUST NOT create duplicate rows;
    Q-MULTI-PROCESS-POSTURE (b) UPSERT-idempotency-by-construction via
    uq_scan_subdomain. Second delivery updates last_probed_at /
    status_code from the new payload."""
    from app.models.recon import AttackSurface

    s = scan_with_jobs
    event_v1 = _attack_surface_event(
        s["scan"],
        s["org"],
        subdomains=[
            {
                "url": "https://api.c.example.com",
                "status": "live",
                "status_code": 200,
                "tech_stack": ["nginx"],
                "last_probed_at": "2026-05-30T14:32:00Z",
            }
        ],
    )
    # v2 changes status_code (e.g., subdomain started returning 503).
    event_v2 = _attack_surface_event(
        s["scan"],
        s["org"],
        subdomains=[
            {
                "url": "https://api.c.example.com",
                "status": "live",
                "status_code": 503,
                "tech_stack": ["nginx", "Apache"],
                "last_probed_at": "2026-05-30T15:00:00Z",
            }
        ],
    )

    consumer = CompletionsConsumer(
        session_factory=session_factory, redis=fake_redis
    )
    await consumer._handle(event_v1)
    await consumer._handle(event_v2)

    async with session_factory() as fresh:
        from sqlalchemy import text as _text
        await fresh.execute(_text(f"SET app.current_org_id = '{s['org'].id}'"))
        rows = (
            await fresh.execute(
                select(AttackSurface).where(AttackSurface.scan_id == s["scan"].id)
            )
        ).scalars().all()
        assert len(rows) == 1, "uq_scan_subdomain must prevent duplicate row"
        assert rows[0].status_code == 503, "UPSERT must apply v2 status_code"
        assert rows[0].tech_stack == ["nginx", "Apache"]


# ---------------------------------------------------------------- 8.3α.3 RLS isolation (cross-org rejection)


@pytest.mark.asyncio
async def test_handle_attack_surface_rls_isolation(
    scan_with_jobs, fake_redis, session_factory
):
    """A second org reading via SET app.current_org_id MUST NOT see
    the first org's AttackSurface rows. Pins RLS isolation per
    ADR-013 + AttackSurface TenantMixin."""
    from app.models.recon import AttackSurface

    s = scan_with_jobs
    event = _attack_surface_event(s["scan"], s["org"])

    consumer = CompletionsConsumer(
        session_factory=session_factory, redis=fake_redis
    )
    await consumer._handle(event)

    # Read as a DIFFERENT org_id — RLS must hide rows.
    other_org_id = uuid4()
    async with session_factory() as fresh:
        from sqlalchemy import text as _text
        await fresh.execute(_text(f"SET app.current_org_id = '{other_org_id}'"))
        rows = (
            await fresh.execute(
                select(AttackSurface).where(AttackSurface.scan_id == s["scan"].id)
            )
        ).scalars().all()
        assert rows == [], "RLS must hide rows from foreign org"


# ---------------------------------------------------------------- 8.3α.4 malformed URL skipped permissively


@pytest.mark.asyncio
async def test_handle_attack_surface_malformed_url_skipped(
    scan_with_jobs, fake_redis, session_factory
):
    """Y-EVENT-PAYLOAD-VALIDATION (b) permissive parse: malformed URL
    entries are skipped silently; well-formed entries in the same event
    still persist."""
    from app.models.recon import AttackSurface

    s = scan_with_jobs
    event = _attack_surface_event(
        s["scan"],
        s["org"],
        subdomains=[
            {"url": "not-a-url-at-all", "status": "live"},  # bad
            {"url": "", "status": "live"},  # bad
            {
                "url": "https://valid.c.example.com",
                "status": "live",
                "status_code": 200,
            },  # good
        ],
    )

    consumer = CompletionsConsumer(
        session_factory=session_factory, redis=fake_redis
    )
    await consumer._handle(event)

    async with session_factory() as fresh:
        from sqlalchemy import text as _text
        await fresh.execute(_text(f"SET app.current_org_id = '{s['org'].id}'"))
        rows = (
            await fresh.execute(
                select(AttackSurface).where(AttackSurface.scan_id == s["scan"].id)
            )
        ).scalars().all()
        assert len(rows) == 1
        assert rows[0].full_url == "https://valid.c.example.com"


# ---------------------------------------------------------------- 8.3α.5 empty subdomains handled as no-op


@pytest.mark.asyncio
async def test_handle_attack_surface_empty_subdomains_handled(
    scan_with_jobs, fake_redis, session_factory
):
    """Empty subdomains array → no INSERT, no error. Pub/Sub at-least-
    once redelivery semantics: still ack the event by returning."""
    from app.models.recon import AttackSurface

    s = scan_with_jobs
    event = _attack_surface_event(s["scan"], s["org"], subdomains=[])

    consumer = CompletionsConsumer(
        session_factory=session_factory, redis=fake_redis
    )
    await consumer._handle(event)  # must not raise

    async with session_factory() as fresh:
        from sqlalchemy import text as _text
        await fresh.execute(_text(f"SET app.current_org_id = '{s['org'].id}'"))
        rows = (
            await fresh.execute(
                select(AttackSurface).where(AttackSurface.scan_id == s["scan"].id)
            )
        ).scalars().all()
        assert rows == []


# ---------------------------------------------------------------- 8.3α.6 missing optional fields tolerated


@pytest.mark.asyncio
async def test_handle_attack_surface_missing_optional_fields(
    scan_with_jobs, fake_redis, session_factory
):
    """status_code / tech_stack / last_probed_at are optional per SPEC
    §7.6; consumer fills last_probed_at from event-level timestamp when
    missing."""
    from app.models.recon import AttackSurface

    s = scan_with_jobs
    event = _attack_surface_event(
        s["scan"],
        s["org"],
        subdomains=[
            {"url": "https://minimal.c.example.com", "status": "dead"},
        ],
    )

    consumer = CompletionsConsumer(
        session_factory=session_factory, redis=fake_redis
    )
    await consumer._handle(event)

    async with session_factory() as fresh:
        from sqlalchemy import text as _text
        await fresh.execute(_text(f"SET app.current_org_id = '{s['org'].id}'"))
        rows = (
            await fresh.execute(
                select(AttackSurface).where(AttackSurface.scan_id == s["scan"].id)
            )
        ).scalars().all()
        assert len(rows) == 1
        r = rows[0]
        assert r.status_code is None
        assert r.tech_stack is None
        # last_probed_at filled from event.timestamp (2026-05-30T14:32:01Z).
        assert r.last_probed_at is not None


# ---------------------------------------------------------------- 8.3α.7 routing dispatch (_handle → _handle_attack_surface)


@pytest.mark.asyncio
async def test_handle_attack_surface_routing_dispatch(
    scan_with_jobs, fake_redis, session_factory, monkeypatch
):
    """_handle(event) with event_type='attack_surface' routes to
    _handle_attack_surface and does NOT fall through to the existing
    job_completed / partial_findings event_seq path. Pins the routing
    surface added in this commit."""
    s = scan_with_jobs
    event = _attack_surface_event(s["scan"], s["org"])

    consumer = CompletionsConsumer(
        session_factory=session_factory, redis=fake_redis
    )

    called = {"attack_surface": 0, "single": 0, "intermediate": 0, "terminal": 0}

    async def _spy_attack(self, ev):
        called["attack_surface"] += 1

    async def _spy_single(self, ev):
        called["single"] += 1

    async def _spy_intermediate(self, ev):
        called["intermediate"] += 1

    async def _spy_terminal(self, ev):
        called["terminal"] += 1

    monkeypatch.setattr(
        CompletionsConsumer, "_handle_attack_surface", _spy_attack
    )
    monkeypatch.setattr(
        CompletionsConsumer, "_handle_single_event", _spy_single
    )
    monkeypatch.setattr(
        CompletionsConsumer, "_handle_intermediate_event", _spy_intermediate
    )
    monkeypatch.setattr(
        CompletionsConsumer, "_handle_terminal_event", _spy_terminal
    )

    await consumer._handle(event)

    assert called == {
        "attack_surface": 1,
        "single": 0,
        "intermediate": 0,
        "terminal": 0,
    }, "attack_surface event MUST route to _handle_attack_surface only"
