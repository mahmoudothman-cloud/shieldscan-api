"""Phase 2 unit tests for the findings-ingest extension to
CompletionsConsumer (per ADR-025).

Scope per the Phase 2 protocol: routing logic + accumulator behavior
in isolation, using mocked session_factory and patched private path
handlers. Database integration tests land in Phase 3.

Tests also pin the Phase-0 / Phase-1 / Phase-2 deviations
behaviorally:
- Deviation 2: ``_handle`` filter accepts both ``job_completed`` AND
  ``partial_findings`` event types (test_handle_event_routes_partial
  _findings_event_type).
- Deviation 4: terminal-event short-circuits when ScanJob already
  terminal (test_terminal_event_short_circuits_when_scanjob_already
  _terminal — implemented at Phase 3 with real DB; routing-side
  Phase-2 pin verifies the call path).
- Deviation 5: accumulator clear only AFTER successful commit
  (test_accumulator_cleared_after_successful_commit /
  test_accumulator_retained_on_commit_failure).
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession as _SQLAS

from app.models.identity import Membership, MembershipRole, Organization, User
from app.models.projects import Project
from app.models.raw_findings import RawFinding as RawFindingModel
from app.models.scans import Scan, ScanJob, ScanStatus, ScanType
from app.services.auth import hash_password
from app.services.completions_consumer import CompletionsConsumer
from app.db.tenant_context import set_tenant_context
from tests.conftest import use_org


# ---------------------------------------------------------------- helpers


def _make_consumer() -> CompletionsConsumer:
    """Construct a CompletionsConsumer with a mock session_factory + redis.

    Tests that exercise routing only never touch the session_factory;
    tests that exercise accumulator behavior touch it via patched
    ``_persist`` (which would otherwise need a real DB).
    """
    return CompletionsConsumer(
        session_factory=MagicMock(),
        redis=MagicMock(),
    )


def _event(
    *,
    event_type: str = "job_completed",
    status: str = "completed",
    total: int = 1,
    index: int = 1,
    findings: list | None = None,
    scan_id: UUID | None = None,
    job_id: UUID | None = None,
    org_id: UUID | None = None,
    finding_count: int | None = None,
) -> dict:
    """Build a minimal event payload."""
    if scan_id is None:
        scan_id = uuid4()
    if job_id is None:
        job_id = uuid4()
    if org_id is None:
        org_id = uuid4()
    if finding_count is None:
        finding_count = len(findings) if findings else 0
    return {
        "event_type": event_type,
        "scan_id": str(scan_id),
        "job_id": str(job_id),
        "organization_id": str(org_id),
        "status": status,
        "finding_count": finding_count,
        "duration_ms": 1000,
        "event_seq": {"index": index, "total": total},
        "findings": findings or [],
    }


# ---------------------------------------------------------------- routing tests


@pytest.mark.asyncio
async def test_handle_event_routes_to_single_event_path() -> None:
    """event_seq.total == 1 + status="completed" → _handle_single_event."""
    c = _make_consumer()
    with patch.object(
        c, "_handle_single_event", new=AsyncMock()
    ) as single, patch.object(
        c, "_handle_intermediate_event", new=AsyncMock()
    ) as intermediate, patch.object(
        c, "_handle_terminal_event", new=AsyncMock()
    ) as terminal, patch.object(
        c, "_handle_failed_or_canceled_event", new=AsyncMock()
    ) as failed:
        await c._handle(_event(status="completed", total=1))
    single.assert_awaited_once()
    intermediate.assert_not_awaited()
    terminal.assert_not_awaited()
    failed.assert_not_awaited()


@pytest.mark.asyncio
async def test_handle_event_routes_to_intermediate_path() -> None:
    """event_seq.total > 1 + status="partial_findings" → _handle_intermediate_event."""
    c = _make_consumer()
    with patch.object(
        c, "_handle_single_event", new=AsyncMock()
    ) as single, patch.object(
        c, "_handle_intermediate_event", new=AsyncMock()
    ) as intermediate, patch.object(
        c, "_handle_terminal_event", new=AsyncMock()
    ) as terminal:
        await c._handle(
            _event(
                event_type="partial_findings",
                status="partial_findings",
                total=3,
                index=1,
            )
        )
    intermediate.assert_awaited_once()
    single.assert_not_awaited()
    terminal.assert_not_awaited()


@pytest.mark.asyncio
async def test_handle_event_routes_to_terminal_path() -> None:
    """event_seq.total > 1 + status="completed" → _handle_terminal_event."""
    c = _make_consumer()
    with patch.object(
        c, "_handle_single_event", new=AsyncMock()
    ) as single, patch.object(
        c, "_handle_intermediate_event", new=AsyncMock()
    ) as intermediate, patch.object(
        c, "_handle_terminal_event", new=AsyncMock()
    ) as terminal:
        await c._handle(_event(status="completed", total=3, index=3))
    terminal.assert_awaited_once()
    single.assert_not_awaited()
    intermediate.assert_not_awaited()


@pytest.mark.asyncio
async def test_handle_event_routes_partial_findings_event_type() -> None:
    """Phase-0 Deviation 2 behavioral pin: the ``_handle`` filter must
    accept ``event_type="partial_findings"`` (not just ``job_completed``).
    A future engineer "tightening" the filter to ``== "job_completed"``
    only would silently drop intermediate sequenced events and break
    the ADR-017 accumulator pattern.
    """
    c = _make_consumer()
    with patch.object(
        c, "_handle_intermediate_event", new=AsyncMock()
    ) as intermediate:
        await c._handle(
            _event(
                event_type="partial_findings",
                status="partial_findings",
                total=2,
                index=1,
            )
        )
    intermediate.assert_awaited_once()


@pytest.mark.asyncio
async def test_handle_event_skips_failed_status() -> None:
    """status="failed" → _handle_failed_or_canceled_event (status-only)."""
    c = _make_consumer()
    with patch.object(
        c, "_handle_failed_or_canceled_event", new=AsyncMock()
    ) as failed, patch.object(
        c, "_handle_single_event", new=AsyncMock()
    ) as single:
        await c._handle(_event(status="failed", findings=[]))
    failed.assert_awaited_once()
    single.assert_not_awaited()


@pytest.mark.asyncio
async def test_handle_event_skips_canceled_status() -> None:
    """status="canceled" → _handle_failed_or_canceled_event (status-only)."""
    c = _make_consumer()
    with patch.object(
        c, "_handle_failed_or_canceled_event", new=AsyncMock()
    ) as failed, patch.object(
        c, "_handle_single_event", new=AsyncMock()
    ) as single:
        await c._handle(_event(status="canceled", findings=[]))
    failed.assert_awaited_once()
    single.assert_not_awaited()


@pytest.mark.asyncio
async def test_handle_event_logs_unknown_status_combo(caplog) -> None:
    """Defensive logging on unknown status + sequencing combinations.

    A new status value (e.g., "running" terminal) routes to the
    defensive log + skip path; surfaces cross-repo drift to engineer
    visibility instead of silently dropping.
    """
    c = _make_consumer()
    with patch.object(
        c, "_handle_single_event", new=AsyncMock()
    ) as single, patch.object(
        c, "_handle_intermediate_event", new=AsyncMock()
    ) as intermediate, patch.object(
        c, "_handle_terminal_event", new=AsyncMock()
    ) as terminal:
        with caplog.at_level("ERROR"):
            await c._handle(_event(status="some_new_status", total=2, index=2))
    single.assert_not_awaited()
    intermediate.assert_not_awaited()
    terminal.assert_not_awaited()
    assert any(
        "unknown status combination" in r.message for r in caplog.records
    )


@pytest.mark.asyncio
async def test_handle_event_ignores_unrecognized_event_types() -> None:
    """event_type outside {job_completed, partial_findings} → silently
    ignored. Defensive against new event types on the channel.
    """
    c = _make_consumer()
    with patch.object(
        c, "_handle_single_event", new=AsyncMock()
    ) as single, patch.object(
        c, "_handle_failed_or_canceled_event", new=AsyncMock()
    ) as failed:
        await c._handle({"event_type": "scan_started", "status": "completed"})
    single.assert_not_awaited()
    failed.assert_not_awaited()


# ---------------------------------------------------------------- accumulator tests


@pytest.mark.asyncio
async def test_accumulator_intermediate_event_accumulates() -> None:
    """Intermediate event appends validated findings to accumulator
    keyed by (scan_id, job_id); no DB write."""
    c = _make_consumer()
    scan_id = uuid4()
    job_id = uuid4()

    finding = {
        "tool_name": "nuclei",
        "engine_category": "dast",
        "title": "XSS",
        "severity": "high",
        "finding_type": "xss",
        "fingerprint": "f" * 64,
        "discovered_at": "2026-05-03T12:00:00Z",
    }

    await c._handle_intermediate_event(
        _event(
            event_type="partial_findings",
            status="partial_findings",
            total=3,
            index=1,
            scan_id=scan_id,
            job_id=job_id,
            findings=[finding, finding],
        )
    )
    key = (scan_id, job_id)
    assert key in c._accumulator
    assert len(c._accumulator[key]) == 2


@pytest.mark.asyncio
async def test_accumulator_lock_prevents_concurrent_modification() -> None:
    """Concurrent intermediate events for the same (scan_id, job_id)
    do not lose data — the asyncio.Lock guards the setdefault+extend
    against task interleaving. Synthesizes 10 concurrent appends each
    of 100 findings; expects 1000 in the accumulator afterward.
    """
    import asyncio as _asyncio

    c = _make_consumer()
    scan_id = uuid4()
    job_id = uuid4()
    finding = {
        "tool_name": "nuclei",
        "engine_category": "dast",
        "title": "XSS",
        "severity": "high",
        "finding_type": "xss",
        "fingerprint": "f" * 64,
        "discovered_at": "2026-05-03T12:00:00Z",
    }
    findings_batch = [finding] * 100

    async def append_batch(idx: int) -> None:
        await c._handle_intermediate_event(
            _event(
                event_type="partial_findings",
                status="partial_findings",
                total=11,
                index=idx,
                scan_id=scan_id,
                job_id=job_id,
                findings=findings_batch,
            )
        )

    await _asyncio.gather(*(append_batch(i) for i in range(1, 11)))
    key = (scan_id, job_id)
    assert len(c._accumulator[key]) == 1000


@pytest.mark.asyncio
async def test_accumulator_cleared_after_successful_commit() -> None:
    """Phase-0 Deviation 5 pin: terminal-event handler clears the
    accumulator entry AFTER ``_persist`` returns True (commit
    succeeded). Mocks ``_persist`` to return True.
    """
    c = _make_consumer()
    scan_id = uuid4()
    job_id = uuid4()
    key = (scan_id, job_id)
    # Pre-seed accumulator with stale data from a hypothetical
    # earlier intermediate event.
    c._accumulator[key] = [{"stub": "data"}]

    finding = {
        "tool_name": "nuclei",
        "engine_category": "dast",
        "title": "XSS",
        "severity": "high",
        "finding_type": "xss",
        "fingerprint": "f" * 64,
        "discovered_at": "2026-05-03T12:00:00Z",
    }

    with patch.object(c, "_persist", new=AsyncMock(return_value=True)):
        await c._handle_terminal_event(
            _event(
                status="completed",
                total=2,
                index=2,
                scan_id=scan_id,
                job_id=job_id,
                findings=[finding],
            )
        )
    assert key not in c._accumulator, (
        "accumulator must be cleared after successful commit"
    )


@pytest.mark.asyncio
async def test_accumulator_retained_on_commit_failure() -> None:
    """Phase-0 Deviation 5 pin: terminal-event handler does NOT clear
    the accumulator if ``_persist`` raises. Pub/Sub redelivery will
    re-fire the terminal event; accumulated batches must be available
    for the retry. Reverse ordering = data-loss-on-commit-failure
    bug; this test guards against that regression.
    """
    c = _make_consumer()
    scan_id = uuid4()
    job_id = uuid4()
    key = (scan_id, job_id)
    c._accumulator[key] = [{"stub": "data"}]

    finding = {
        "tool_name": "nuclei",
        "engine_category": "dast",
        "title": "XSS",
        "severity": "high",
        "finding_type": "xss",
        "fingerprint": "f" * 64,
        "discovered_at": "2026-05-03T12:00:00Z",
    }

    persist_mock = AsyncMock(side_effect=RuntimeError("simulated commit fail"))
    with patch.object(c, "_persist", new=persist_mock):
        with pytest.raises(RuntimeError):
            await c._handle_terminal_event(
                _event(
                    status="completed",
                    total=2,
                    index=2,
                    scan_id=scan_id,
                    job_id=job_id,
                    findings=[finding],
                )
            )
    assert key in c._accumulator, (
        "accumulator must retain data when commit raises (retry-via-"
        "redelivery semantics)"
    )


@pytest.mark.asyncio
async def test_accumulator_cleared_when_persist_short_circuits() -> None:
    """When ``_persist`` returns False (peer worker handled the job —
    Phase-0 Deviation 4 short-circuit), the terminal-event handler
    still clears the accumulator. Otherwise stale data leaks until
    process restart.
    """
    c = _make_consumer()
    scan_id = uuid4()
    job_id = uuid4()
    key = (scan_id, job_id)
    c._accumulator[key] = [{"stub": "data"}]

    finding = {
        "tool_name": "nuclei",
        "engine_category": "dast",
        "title": "XSS",
        "severity": "high",
        "finding_type": "xss",
        "fingerprint": "f" * 64,
        "discovered_at": "2026-05-03T12:00:00Z",
    }

    with patch.object(c, "_persist", new=AsyncMock(return_value=False)):
        await c._handle_terminal_event(
            _event(
                status="completed",
                total=2,
                index=2,
                scan_id=scan_id,
                job_id=job_id,
                findings=[finding],
            )
        )
    assert key not in c._accumulator


# ---------------------------------------------------------------- finding_dicts builder


def test_build_finding_dicts_excludes_scan_id_and_org_id() -> None:
    """Phase-0 Deviation 1 pin: ``_build_finding_dicts`` strips
    per-finding ``scan_id`` / ``org_id`` from Pydantic output. The
    consumer overrides both with ScanJob-derived values during
    ``_persist``; including the per-finding values would be
    redundant at best and conflicting at worst.
    """
    c = _make_consumer()
    raw = {
        "tool_name": "nuclei",
        "engine_category": "dast",
        "title": "XSS",
        "severity": "high",
        "finding_type": "xss",
        "fingerprint": "f" * 64,
        "discovered_at": "2026-05-03T12:00:00Z",
        "scan_id": str(uuid4()),  # engine processor populates these
        "org_id": str(uuid4()),
    }
    dicts = c._build_finding_dicts([raw])
    assert len(dicts) == 1
    assert "scan_id" not in dicts[0]
    assert "org_id" not in dicts[0]
    assert dicts[0]["tool_name"] == "nuclei"


def test_build_finding_dicts_uses_python_field_names_not_aliases() -> None:
    """Phase-2 Adaptation 2 pin: model_dump uses by_alias=False so
    SQLAlchemy column names land in the dict (``mobile_permission``,
    ``mobile_component_name``) rather than wire-format aliases
    (``permission``, ``component_name``). Inserting wire aliases would
    fail with unknown-column errors at SQLAlchemy bind time.
    """
    c = _make_consumer()
    raw = {
        "tool_name": "mobsf",
        "engine_category": "mobile",
        "title": "READ_SMS permission",
        "severity": "medium",
        "finding_type": "permission",
        "fingerprint": "f" * 64,
        "discovered_at": "2026-05-03T12:00:00Z",
        "mobile_os": "android",
        "permission": "android.permission.READ_SMS",  # wire alias
        "component_name": "com.example.LoginActivity",  # wire alias
    }
    dicts = c._build_finding_dicts([raw])
    assert "mobile_permission" in dicts[0]
    assert dicts[0]["mobile_permission"] == "android.permission.READ_SMS"
    assert "mobile_component_name" in dicts[0]
    assert dicts[0]["mobile_component_name"] == "com.example.LoginActivity"
    # Wire aliases must NOT appear (SQLAlchemy has no such columns).
    assert "permission" not in dicts[0]
    assert "component_name" not in dicts[0]


def test_build_finding_dicts_empty_input_returns_empty() -> None:
    """Empty findings → empty dicts list (caller's status-only path
    stays cheap).
    """
    c = _make_consumer()
    assert c._build_finding_dicts([]) == []


def test_build_finding_dicts_validates_via_pydantic() -> None:
    """Invalid finding raises ValidationError (Pydantic strictness)."""
    from pydantic import ValidationError

    c = _make_consumer()
    raw = {
        "tool_name": "nuclei",
        # missing required fields
    }
    with pytest.raises(ValidationError):
        c._build_finding_dicts([raw])


# ============================================================================
# PHASE 3 INTEGRATION TESTS
# ============================================================================
# Full DB-backed tests; reuse fixtures from
# tests/services/test_completions_consumer.py (scan_with_jobs +
# session_factory) for the Organization + Scan + ScanJob graph.
# Tests below import them via pytest's fixture discovery; the fixtures
# live in the sibling test file but pytest_asyncio resolves them
# across services/ when imported.

# Fixture re-defined here (vs imported) because pytest fixture discovery
# requires fixtures to be in conftest.py or the same file as their tests.
# Identical to the one in test_completions_consumer.py to share semantics.


@pytest_asyncio.fixture
async def session_factory_int(db_session):
    """Test-scoped session factory bound to the same AsyncConnection
    as db_session. See test_completions_consumer.py session_factory
    for the full rationale.
    """
    connection = db_session.bind

    class _Factory:
        async def __aenter__(self):
            self._session = _SQLAS(bind=connection, expire_on_commit=False)
            return self._session

        async def __aexit__(self, *exc):
            await self._session.close()

    def _factory():
        return _Factory()

    return _factory


@pytest_asyncio.fixture
async def scan_with_jobs_int(db_session):
    """Persisted Scan + 3 ScanJob rows in `running` state."""
    org = Organization(name="Ingest Org", slug=f"ing-{uuid4().hex[:8]}")
    db_session.add(org)
    await db_session.flush()
    await use_org(db_session, org.id)

    user = User(
        email=f"i-{uuid4().hex[:6]}@t.co",
        hashed_password=hash_password("IPass-1"),
        full_name="I",
        email_verified=True,
    )
    db_session.add(user)
    await db_session.flush()
    db_session.add(
        Membership(user_id=user.id, organization_id=org.id, role=MembershipRole.ADMIN)
    )

    project = Project(
        organization_id=org.id,
        name="IApp",
        target_url="https://i.example.com",
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
            target_url="https://i.example.com",
            status="running",
            idempotency_key=f"{scan.id}:{engine}:1234567890",
        )
        for engine in ("nuclei", "semgrep", "gitleaks")
    ]
    for j in jobs:
        db_session.add(j)
    await db_session.commit()

    return {"org": org, "scan": scan, "jobs": jobs}


def _wire_finding(**overrides) -> dict:
    """Build a Pydantic-validatable finding dict matching engine wire format."""
    base = {
        "tool_name": "nuclei",
        "engine_category": "dast",
        "title": "XSS",
        "severity": "high",
        "finding_type": "xss",
        "fingerprint": "f" * 64,
        "discovered_at": "2026-05-03T12:00:00Z",
    }
    base.update(overrides)
    return base


def _completion_event_for_job(job, *, status="completed", findings=None,
                              total=1, index=1, finding_count=None):
    """Synthesize a job_completed event for one of the test ScanJobs."""
    if findings is None:
        findings = []
    if finding_count is None:
        finding_count = len(findings)
    event_type = (
        "partial_findings"
        if status == "partial_findings"
        else "job_completed"
    )
    return {
        "event_type": event_type,
        "job_id": str(job.id),
        "scan_id": str(job.scan_id),
        "organization_id": str(job.organization_id),
        "engine": job.engine,
        "status": status,
        "finding_count": finding_count,
        "duration_ms": 1234,
        "idempotency_key": job.idempotency_key,
        "timestamp": "2026-05-03T12:00:00Z",
        "event_seq": {"index": index, "total": total},
        "findings": findings,
    }


# ---------------------------------------------------------------- 1. single-event E2E


@pytest.mark.asyncio
async def test_single_event_inserts_findings_and_updates_scanjob(
    scan_with_jobs_int, fake_redis, session_factory_int,
):
    """Full E2E: single event with 3 findings → 3 raw_findings rows
    persisted (with correct organization_id + scan_id) AND ScanJob.status
    updated atomically."""
    s = scan_with_jobs_int
    job = s["jobs"][0]

    findings = [
        _wire_finding(fingerprint="a" * 64, finding_type="xss"),
        _wire_finding(fingerprint="b" * 64, finding_type="sqli"),
        _wire_finding(fingerprint="c" * 64, finding_type="csrf"),
    ]
    event = _completion_event_for_job(job, findings=findings, finding_count=3)

    consumer = CompletionsConsumer(
        session_factory=session_factory_int, redis=fake_redis
    )
    await consumer._handle(event)

    # Verify findings persisted with correct org + scan + tool_name.
    async with session_factory_int() as fresh:
        await set_tenant_context(fresh, s['org'].id)
        rows = (
            await fresh.execute(
                select(RawFindingModel).where(
                    RawFindingModel.scan_id == s["scan"].id
                )
            )
        ).scalars().all()
        assert len(rows) == 3
        assert {r.fingerprint for r in rows} == {"a" * 64, "b" * 64, "c" * 64}
        assert all(r.organization_id == s["org"].id for r in rows)
        assert all(r.scan_id == s["scan"].id for r in rows)

        # ScanJob updated atomically in the same transaction.
        updated = (
            await fresh.execute(select(ScanJob).where(ScanJob.id == job.id))
        ).scalar_one()
        assert updated.status == "completed"
        assert updated.finding_count == 3
        assert updated.duration_ms == 1234


# ---------------------------------------------------------------- 2. RLS preamble


@pytest.mark.asyncio
async def test_rls_session_local_set_before_insert(
    scan_with_jobs_int, fake_redis, session_factory_int,
):
    """Verify the SET app.current_org_id RLS preamble executes before
    the bulk insert. Approach: cross-org READ rejection downstream — if
    the SET didn't fire, we'd be unable to insert under RLS WITH CHECK
    at all; reaching the post-insert assertion proves SET succeeded.

    Direct verification path: after consumer commits, query under a
    DIFFERENT org's RLS context and assert the inserted findings are
    NOT visible. Then re-query under the correct org and assert they
    ARE visible.
    """
    s = scan_with_jobs_int
    job = s["jobs"][0]

    # Create a second org (sibling) for the cross-org RLS check.
    async with session_factory_int() as bootstrap:
        await set_tenant_context(bootstrap, s['org'].id)
        other_org = Organization(name="Other", slug=f"other-{uuid4().hex[:8]}")
        bootstrap.add(other_org)
        await bootstrap.commit()
        other_org_id = other_org.id

    findings = [_wire_finding(fingerprint="rls-1" + "0" * 59)]
    event = _completion_event_for_job(job, findings=findings, finding_count=1)

    consumer = CompletionsConsumer(
        session_factory=session_factory_int, redis=fake_redis
    )
    await consumer._handle(event)

    # Read under the OTHER org's context — RLS must hide the finding.
    async with session_factory_int() as fresh:
        await set_tenant_context(fresh, other_org_id)
        rows = (
            await fresh.execute(
                select(RawFindingModel).where(
                    RawFindingModel.scan_id == s["scan"].id
                )
            )
        ).scalars().all()
        assert rows == [], (
            "RLS must hide findings from foreign org context; if rows "
            "are visible, SET app.current_org_id was not applied "
            "correctly during the consumer's insert"
        )

    # Read under the CORRECT org's context — RLS must show the finding.
    async with session_factory_int() as fresh:
        await set_tenant_context(fresh, s['org'].id)
        rows = (
            await fresh.execute(
                select(RawFindingModel).where(
                    RawFindingModel.scan_id == s["scan"].id
                )
            )
        ).scalars().all()
        assert len(rows) == 1


# ---------------------------------------------------------------- 3. atomic rollback


@pytest.mark.asyncio
async def test_atomic_txn_rollback_on_insert_failure(
    scan_with_jobs_int, fake_redis, session_factory_int,
):
    """Force a constraint violation mid-insert; verify NO raw_findings
    rows persisted AND ScanJob.status unchanged.

    Approach: inject finding_dicts with a NULL ``tool_name`` (NOT NULL
    constraint at the DB level). Bypass _build_finding_dicts so
    Pydantic validation doesn't intervene; call _persist directly with
    the malformed dict.
    """
    s = scan_with_jobs_int
    job = s["jobs"][0]

    bad_dicts = [
        {
            "tool_name": None,  # NOT NULL violation
            "engine_category": "dast",
            "title": "doomed",
            "severity": "high",
            "finding_type": "xss",
            "fingerprint": "x" * 64,
            "discovered_at": "2026-05-03T12:00:00Z",
        }
    ]
    event = _completion_event_for_job(job, findings=[], finding_count=99)

    consumer = CompletionsConsumer(
        session_factory=session_factory_int, redis=fake_redis
    )
    with pytest.raises(Exception):  # IntegrityError or wrapped DBAPIError
        await consumer._persist(event, finding_dicts=bad_dicts)

    # Verify rollback: no rows + ScanJob unchanged.
    async with session_factory_int() as fresh:
        await set_tenant_context(fresh, s['org'].id)
        rows = (
            await fresh.execute(
                select(RawFindingModel).where(
                    RawFindingModel.scan_id == s["scan"].id
                )
            )
        ).scalars().all()
        assert rows == [], "rollback must leave raw_findings table empty"

        unchanged = (
            await fresh.execute(select(ScanJob).where(ScanJob.id == job.id))
        ).scalar_one()
        assert unchanged.status == "running", (
            "rollback must leave ScanJob.status unchanged"
        )
        assert unchanged.finding_count == 0
        assert unchanged.duration_ms is None


# ---------------------------------------------------------------- 4. RLS isolation


@pytest.mark.asyncio
async def test_org_isolation_via_rls(
    scan_with_jobs_int, fake_redis, session_factory_int,
):
    """Under cross-org context, raw_findings SELECT returns empty.
    Symmetric pin to test_rls_session_local_set_before_insert (this
    one focuses on the read side; that one focused on the SET-fired
    proof)."""
    s = scan_with_jobs_int
    job = s["jobs"][0]

    findings = [
        _wire_finding(fingerprint=("iso" + str(i).zfill(2)) + "0" * 59)
        for i in range(5)
    ]
    event = _completion_event_for_job(job, findings=findings, finding_count=5)

    consumer = CompletionsConsumer(
        session_factory=session_factory_int, redis=fake_redis
    )
    await consumer._handle(event)

    # Set up a foreign org context.
    async with session_factory_int() as fresh:
        await set_tenant_context(fresh, s['org'].id)
        foreign_org = Organization(name="Foreign", slug=f"frgn-{uuid4().hex[:8]}")
        fresh.add(foreign_org)
        await fresh.commit()
        foreign_org_id = foreign_org.id

    # Cross-org SELECT — RLS hides everything.
    async with session_factory_int() as fresh:
        await set_tenant_context(fresh, foreign_org_id)
        rows = (
            await fresh.execute(select(RawFindingModel))
        ).scalars().all()
        assert rows == [], "cross-org RLS must hide all findings"


# ---------------------------------------------------------------- 5. bulk-insert perf


@pytest.mark.asyncio
async def test_bulk_insert_performance_under_1000_findings_under_500ms(
    scan_with_jobs_int, fake_redis, session_factory_int,
):
    """Pre-launch perf gate: 1000-finding event commits in <500ms.

    SQLAlchemy 2.0 Core construct (insert(RawFinding) + executemany
    list) should comfortably hit this on local PostgreSQL. If this
    fails, investigate whether ORM add_all crept in (~5-10x slower).
    """
    import time as _time

    s = scan_with_jobs_int
    job = s["jobs"][0]

    findings = [
        _wire_finding(
            fingerprint=("perf" + str(i).zfill(60))[:64],
            finding_type=f"type-{i % 10}",
        )
        for i in range(1000)
    ]
    event = _completion_event_for_job(
        job, findings=findings, finding_count=1000
    )

    consumer = CompletionsConsumer(
        session_factory=session_factory_int, redis=fake_redis
    )

    start = _time.perf_counter()
    await consumer._handle(event)
    elapsed = _time.perf_counter() - start
    assert elapsed < 0.5, (
        f"bulk insert of 1000 findings must complete in <500ms; took "
        f"{elapsed:.3f}s — investigate ORM regression vs Core insert"
    )

    # Sanity: rows landed.
    async with session_factory_int() as fresh:
        await set_tenant_context(fresh, s['org'].id)
        count = (
            await fresh.execute(
                select(RawFindingModel).where(
                    RawFindingModel.scan_id == s["scan"].id
                )
            )
        ).scalars().all()
        assert len(count) == 1000


# ----------------------------------------------------------------------------
# ADR-017 FORCING-FUNCTION TEST PIN (LOAD-BEARING)
# Per ADR-017 line 1474-1475 and design doc §7.5
# ----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_consumer_aggregates_sequenced_findings(
    scan_with_jobs_int, fake_redis, session_factory_int,
):
    """ADR-017 forcing-function test pin (LOAD-BEARING).

    Per ADR-017 line 1474-1475 and the SPEC §7.3 sequencing contract:
    workers producing >1000 findings emit multiple events with
    event_seq.total > 1. Intermediate events (event_seq.index < total)
    use status="partial_findings" and accumulate; the terminal event
    (event_seq.index == total) carries the canonical status +
    authoritative finding_count and triggers the single-transaction
    commit of all accumulated findings.

    This test synthesizes a 3-event × 833 + 833 + 834 = 2500-finding
    sequence and asserts:

      - Events 1+2 produce ZERO raw_findings rows (accumulator only).
      - ScanJob.status remains "running" after events 1+2.
      - Event 3 (terminal) produces 2500 raw_findings rows in a single
        transaction.
      - ScanJob.status updates to "completed" + finding_count = 2500.
      - Accumulator key (scan_id, job_id) cleared after the commit.

    If this test fails or is skipped, the ADR-017 forcing-function
    contract is unmet and the Phase 4 commit MUST NOT land.
    """
    s = scan_with_jobs_int
    job = s["jobs"][0]
    org_id = s["org"].id

    # Build 2500 findings across 3 batches of 833 + 833 + 834.
    def _findings_batch(start: int, count: int) -> list[dict]:
        return [
            _wire_finding(
                fingerprint=("seq" + str(start + i).zfill(61))[:64],
                finding_type=f"type-{(start + i) % 10}",
            )
            for i in range(count)
        ]

    batch_1 = _findings_batch(0, 833)
    batch_2 = _findings_batch(833, 833)
    batch_3 = _findings_batch(1666, 834)

    event_1 = _completion_event_for_job(
        job,
        status="partial_findings",
        findings=batch_1,
        total=3,
        index=1,
        finding_count=0,  # intermediate; not authoritative
    )
    event_2 = _completion_event_for_job(
        job,
        status="partial_findings",
        findings=batch_2,
        total=3,
        index=2,
        finding_count=0,
    )
    event_3 = _completion_event_for_job(
        job,
        status="completed",
        findings=batch_3,
        total=3,
        index=3,
        finding_count=2500,  # authoritative per ADR-017 line 822
    )

    consumer = CompletionsConsumer(
        session_factory=session_factory_int, redis=fake_redis
    )

    # Process event 1 (intermediate).
    await consumer._handle(event_1)

    # Assert: accumulator has 833 entries; no DB writes.
    key = (UUID(str(job.scan_id)), UUID(str(job.id)))
    assert key in consumer._accumulator
    assert len(consumer._accumulator[key]) == 833

    async with session_factory_int() as fresh:
        await set_tenant_context(fresh, org_id)
        rows = (
            await fresh.execute(
                select(RawFindingModel).where(
                    RawFindingModel.scan_id == s["scan"].id
                )
            )
        ).scalars().all()
        assert rows == [], (
            "intermediate event must NOT write raw_findings rows"
        )
        running_job = (
            await fresh.execute(select(ScanJob).where(ScanJob.id == job.id))
        ).scalar_one()
        assert running_job.status == "running", (
            "intermediate event must NOT update ScanJob.status"
        )

    # Process event 2 (intermediate).
    await consumer._handle(event_2)

    # Assert: accumulator has 1666; still no DB writes.
    assert len(consumer._accumulator[key]) == 1666

    async with session_factory_int() as fresh:
        await set_tenant_context(fresh, org_id)
        rows = (
            await fresh.execute(
                select(RawFindingModel).where(
                    RawFindingModel.scan_id == s["scan"].id
                )
            )
        ).scalars().all()
        assert rows == [], (
            "second intermediate event must NOT write raw_findings rows"
        )
        running_job = (
            await fresh.execute(select(ScanJob).where(ScanJob.id == job.id))
        ).scalar_one()
        assert running_job.status == "running"

    # Process event 3 (terminal). Single transaction commits 2500
    # findings + ScanJob update atomically.
    await consumer._handle(event_3)

    # Assert: 2500 rows persisted; ScanJob updated; accumulator cleared.
    async with session_factory_int() as fresh:
        await set_tenant_context(fresh, org_id)
        rows = (
            await fresh.execute(
                select(RawFindingModel).where(
                    RawFindingModel.scan_id == s["scan"].id
                )
            )
        ).scalars().all()
        assert len(rows) == 2500, (
            f"ADR-017 contract: terminal event must commit "
            f"all 2500 accumulated findings in one transaction; got "
            f"{len(rows)}"
        )

        committed_job = (
            await fresh.execute(select(ScanJob).where(ScanJob.id == job.id))
        ).scalar_one()
        assert committed_job.status == "completed"
        assert committed_job.finding_count == 2500

    assert key not in consumer._accumulator, (
        "ADR-017 contract: accumulator key must be cleared after "
        "successful terminal-event commit"
    )


# ---------------------------------------------------------------- edge cases


@pytest.mark.asyncio
async def test_failed_status_no_findings_ingest(
    scan_with_jobs_int, fake_redis, session_factory_int,
):
    """status="failed" → ScanJob.status updates; no raw_findings inserted."""
    s = scan_with_jobs_int
    job = s["jobs"][0]
    event = _completion_event_for_job(job, status="failed", findings=[])

    consumer = CompletionsConsumer(
        session_factory=session_factory_int, redis=fake_redis
    )
    await consumer._handle(event)

    async with session_factory_int() as fresh:
        await set_tenant_context(fresh, s['org'].id)
        rows = (
            await fresh.execute(
                select(RawFindingModel).where(
                    RawFindingModel.scan_id == s["scan"].id
                )
            )
        ).scalars().all()
        assert rows == []

        updated = (
            await fresh.execute(select(ScanJob).where(ScanJob.id == job.id))
        ).scalar_one()
        assert updated.status == "failed"


@pytest.mark.asyncio
async def test_canceled_status_no_findings_ingest(
    scan_with_jobs_int, fake_redis, session_factory_int,
):
    """status="canceled" → ScanJob.status updates; no raw_findings inserted."""
    s = scan_with_jobs_int
    job = s["jobs"][0]
    event = _completion_event_for_job(job, status="canceled", findings=[])

    consumer = CompletionsConsumer(
        session_factory=session_factory_int, redis=fake_redis
    )
    await consumer._handle(event)

    async with session_factory_int() as fresh:
        await set_tenant_context(fresh, s['org'].id)
        rows = (
            await fresh.execute(
                select(RawFindingModel).where(
                    RawFindingModel.scan_id == s["scan"].id
                )
            )
        ).scalars().all()
        assert rows == []

        updated = (
            await fresh.execute(select(ScanJob).where(ScanJob.id == job.id))
        ).scalar_one()
        assert updated.status == "canceled"


@pytest.mark.asyncio
async def test_findings_array_empty_no_insert(
    scan_with_jobs_int, fake_redis, session_factory_int,
):
    """status="completed" but findings=[] → just status update; no inserts.

    Realistic case: clean scan (tool ran successfully but found nothing).
    """
    s = scan_with_jobs_int
    job = s["jobs"][0]
    event = _completion_event_for_job(
        job, status="completed", findings=[], finding_count=0
    )

    consumer = CompletionsConsumer(
        session_factory=session_factory_int, redis=fake_redis
    )
    await consumer._handle(event)

    async with session_factory_int() as fresh:
        await set_tenant_context(fresh, s['org'].id)
        rows = (
            await fresh.execute(
                select(RawFindingModel).where(
                    RawFindingModel.scan_id == s["scan"].id
                )
            )
        ).scalars().all()
        assert rows == []

        updated = (
            await fresh.execute(select(ScanJob).where(ScanJob.id == job.id))
        ).scalar_one()
        assert updated.status == "completed"
        assert updated.finding_count == 0
