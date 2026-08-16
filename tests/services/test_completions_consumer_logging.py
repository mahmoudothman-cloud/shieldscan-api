"""Job-completion logging tests for ``CompletionsConsumer``.

Pins the ``job_completed`` INFO line emitted by ``_persist`` after commit.
This is a feature, not a regression repair: no logging call in either repo
had ever emitted these fields, and the API configures no logging handler
that could have dropped them.

What is pinned:
  1. The line is emitted for EVERY terminal outcome — completed, failed and
     canceled — not just the happy path. A failed or canceled job is the
     case most worth having in the log, and it is the one an
     only-on-success implementation would silently omit.
  2. It carries all eight fields: engine, status, finding_count,
     persisted_count, duration_ms, scan_id, job_id, idempotency_key —
     plus error_message, rendered only when the event carries one but
     always present in ``extra`` so the structured shape is stable.
  3. finding_count and persisted_count are independent — persisted_count
     reflects what actually survived validation into ``raw_findings``, not
     a copy of the engine's claim. This is the silent-loss condition that
     hid nmap producing zero findings for 14 consecutive runs while every
     status field read "completed".
  4. engine / idempotency_key fall back to the ScanJob row when the event
     omits them (both are ``omitempty`` on the Go side).
  5. Rejection logging LEVELS in ``_build_finding_dicts``: per-finding
     detail at WARNING (it was DEBUG, which produced no output at all in a
     process with no logging configuration) and the aggregate at ERROR,
     with detail capped and the total-loss case called out.

Assertions run against the RENDERED message as well as the ``extra``
attributes. The API installs no structured formatter today, so the
rendered message is what actually reaches the log; a test that checked
only ``extra`` would pass on a line that prints none of the fields.
"""

from __future__ import annotations

import logging
from unittest.mock import MagicMock
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession as _SQLAS

from app.db.tenant_context import TenantSession as _TenantSession
from app.models.identity import Membership, MembershipRole, Organization, User
from app.models.projects import Project
from app.models.scans import Scan, ScanJob, ScanStatus, ScanType
from app.services.auth import hash_password
from app.services.completions_consumer import CompletionsConsumer
from tests.conftest import use_org

LOGGER_NAME = "app.services.completions_consumer"


# ---------------------------------------------------------------- fixtures


@pytest_asyncio.fixture
async def session_factory(db_session):
    """Session factory bound to the test's AsyncConnection.

    ``sync_session_class=TenantSession`` mirrors production
    ``AsyncSessionLocal``; a bare AsyncSession would bypass the
    ``after_begin`` tenant re-apply and the tenant guard. See
    test_completions_consumer.py for the full rationale.
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
    """Persisted Scan + 3 running ScanJob rows (nmap first — the engine
    whose silent loss motivated persisted_count)."""
    org = Organization(name="Log Org", slug=f"log-{uuid4().hex[:8]}")
    db_session.add(org)
    await db_session.flush()
    await use_org(db_session, org.id)

    user = User(
        email=f"l-{uuid4().hex[:6]}@t.co",
        hashed_password=hash_password("LPass-1"),
        full_name="L",
        email_verified=True,
    )
    db_session.add(user)
    await db_session.flush()
    db_session.add(
        Membership(
            user_id=user.id, organization_id=org.id, role=MembershipRole.ADMIN
        )
    )

    project = Project(
        organization_id=org.id,
        name="LApp",
        target_url="https://l.example.com",
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
            target_url="https://l.example.com",
            status="running",
            idempotency_key=f"{scan.id}:{engine}:1234567890",
        )
        for engine in ("nmap", "nuclei", "sslyze")
    ]
    for j in jobs:
        db_session.add(j)
    await db_session.commit()

    return {"org": org, "scan": scan, "jobs": jobs}


# ---------------------------------------------------------------- helpers


def _event(job, *, status="completed", findings=None, finding_count=None,
           duration_ms=1234, error_message=None):
    findings = findings or []
    if finding_count is None:
        finding_count = len(findings)
    event = {
        "event_type": "job_completed",
        "job_id": str(job.id),
        "scan_id": str(job.scan_id),
        "organization_id": str(job.organization_id),
        "engine": job.engine,
        "status": status,
        "finding_count": finding_count,
        "duration_ms": duration_ms,
        "idempotency_key": job.idempotency_key,
        "timestamp": "2026-08-16T12:00:00Z",
        "event_seq": {"index": 1, "total": 1},
        "findings": findings,
    }
    # Absent rather than None when unset — the Go side omits the key
    # entirely on success (`omitempty`), and the handler distinguishes the
    # two, so the fixture must too.
    if error_message is not None:
        event["error_message"] = error_message
    return event


def _valid_finding(**overrides) -> dict:
    base = {
        "tool_name": "nuclei",
        "engine_category": "dast",
        "title": "XSS",
        "severity": "high",
        "finding_type": "xss",
        "fingerprint": "f" * 64,
        "discovered_at": "2026-08-16T12:00:00Z",
    }
    base.update(overrides)
    return base


def _job_completed_lines(caplog) -> list[logging.LogRecord]:
    """Records selected by their RENDERED message, not by an extra
    attribute — so a line that carries the fields only in ``extra``
    and prints nothing does not satisfy these tests."""
    return [
        rec
        for rec in caplog.records
        if rec.name == LOGGER_NAME
        and rec.getMessage().startswith("job_completed ")
    ]


# ---------------------------------------------------------------- 1. every terminal outcome


@pytest.mark.parametrize("status", ["completed", "failed", "canceled"])
@pytest.mark.asyncio
async def test_job_completed_line_emitted_with_all_fields(
    status, scan_with_jobs, fake_redis, session_factory, caplog
):
    """One INFO line per job carrying all eight fields — on the failure
    and cancel paths as well as the success path.

    ``failed`` and ``canceled`` route through
    ``_handle_failed_or_canceled_event``, a different handler from
    ``_handle_single_event``; both converge on ``_persist``, and this
    asserts that convergence rather than assuming it.
    """
    s = scan_with_jobs
    job = s["jobs"][1]  # nuclei
    findings = [_valid_finding()] if status == "completed" else []
    event = _event(job, status=status, findings=findings)

    consumer = CompletionsConsumer(
        session_factory=session_factory, redis=fake_redis
    )
    with caplog.at_level(logging.INFO, logger=LOGGER_NAME):
        await consumer._handle(event)

    lines = _job_completed_lines(caplog)
    assert len(lines) == 1, (
        f"expected exactly one job_completed line for status={status}, "
        f"got {[r.getMessage() for r in lines]}"
    )
    rec = lines[0]
    assert rec.levelno == logging.INFO

    expected = {
        "engine": "nuclei",
        "status": status,
        "finding_count": len(findings),
        "persisted_count": len(findings),
        "duration_ms": 1234,
        "scan_id": str(job.scan_id),
        "job_id": str(job.id),
        "idempotency_key": job.idempotency_key,
    }

    message = rec.getMessage()
    for key, value in expected.items():
        # Rendered output — what actually lands in the log today.
        assert f"{key}={value}" in message, (
            f"{key}={value} missing from rendered line: {message}"
        )
        # Structured attributes — what a JSON formatter would pick up.
        assert getattr(rec, key) == value, (
            f"extra[{key}] was {getattr(rec, key, '<unset>')!r}, "
            f"expected {value!r}"
        )

    assert getattr(rec, "event") == "job_completed"


# ---------------------------------------------------------------- 2. the divergence


@pytest.mark.asyncio
async def test_persisted_count_diverges_from_finding_count_on_dropped_findings(
    scan_with_jobs, fake_redis, session_factory, caplog
):
    """The silent-loss condition, made visible on one line.

    The nmap job claims 3 findings and sends 3 that fail
    ``RawFindingCreate`` validation — the shape of the failure that hid
    nmap for 14 runs. The nuclei job in the same test sends 2 valid
    findings and is the positive control: without it, a
    ``persisted_count`` hardcoded to 0 would pass.
    """
    s = scan_with_jobs
    nmap_job, nuclei_job = s["jobs"][0], s["jobs"][1]

    # Malformed: missing every required field except tool_name, and
    # RawFindingCreate is extra="forbid".
    dropped = [{"tool_name": "nmap", "title": f"port {p} open"} for p in
               (22, 80, 443)]
    kept = [
        _valid_finding(fingerprint=c * 64, title=f"XSS {c}")
        for c in ("a", "b")
    ]

    consumer = CompletionsConsumer(
        session_factory=session_factory, redis=fake_redis
    )
    with caplog.at_level(logging.INFO, logger=LOGGER_NAME):
        await consumer._handle(
            _event(nmap_job, findings=dropped, finding_count=3)
        )
        await consumer._handle(_event(nuclei_job, findings=kept))

    lines = _job_completed_lines(caplog)
    assert len(lines) == 2
    by_engine = {rec.engine: rec for rec in lines}

    # Loss: engine asserted 3, zero rows landed.
    assert by_engine["nmap"].finding_count == 3
    assert by_engine["nmap"].persisted_count == 0
    assert "finding_count=3 persisted_count=0" in by_engine["nmap"].getMessage()

    # Positive control: counts agree when nothing is dropped.
    assert by_engine["nuclei"].finding_count == 2
    assert by_engine["nuclei"].persisted_count == 2
    assert (
        "finding_count=2 persisted_count=2" in by_engine["nuclei"].getMessage()
    )


# ---------------------------------------------------------------- 3. error_message


@pytest.mark.asyncio
async def test_failed_job_line_carries_the_error_message(
    scan_with_jobs, fake_redis, session_factory, caplog
):
    """A failure line without the reason sends you to the DB — where the
    reason is not, since scan_jobs.error_message is never written. The text
    is quoted so its spaces cannot fake a key=value boundary, and it comes
    last so the fixed fields stay in a stable position.
    """
    s = scan_with_jobs
    job = s["jobs"][2]  # sslyze
    reason = "dial tcp 185.247.117.235:443: connect: connection refused"

    consumer = CompletionsConsumer(
        session_factory=session_factory, redis=fake_redis
    )
    with caplog.at_level(logging.INFO, logger=LOGGER_NAME):
        await consumer._handle(
            _event(job, status="failed", error_message=reason)
        )

    rec = _job_completed_lines(caplog)[0]
    assert rec.error_message == reason

    message = rec.getMessage()
    assert f"error_message={reason!r}" in message
    # Last on the line, after the fixed fields.
    assert message.index("error_message=") > message.index("idempotency_key=")


@pytest.mark.asyncio
async def test_successful_job_line_omits_error_message_but_extra_keeps_it(
    scan_with_jobs, fake_redis, session_factory, caplog
):
    """Rendered output stays clean on the happy path, while ``extra`` keeps
    a stable field set so a structured handler doesn't see a shape that
    changes with the outcome."""
    s = scan_with_jobs
    job = s["jobs"][1]

    consumer = CompletionsConsumer(
        session_factory=session_factory, redis=fake_redis
    )
    with caplog.at_level(logging.INFO, logger=LOGGER_NAME):
        await consumer._handle(_event(job, findings=[_valid_finding()]))

    rec = _job_completed_lines(caplog)[0]
    assert "error_message" not in rec.getMessage()
    assert rec.error_message is None


# ---------------------------------------------------------------- 4. rejection levels


def _reject_records(caplog) -> list[logging.LogRecord]:
    return [
        rec
        for rec in caplog.records
        if rec.name == LOGGER_NAME and "rejected" in rec.getMessage()
    ]


def test_rejected_findings_log_detail_at_warning_and_aggregate_at_error(caplog):
    """Levels, not just presence.

    The per-finding reason was at DEBUG and the aggregate at WARNING. With
    no logging configuration in the API, DEBUG produced no output at all —
    so the one line explaining WHY a finding was dropped never existed.
    Detail is now WARNING and the aggregate is ERROR.
    """
    consumer = CompletionsConsumer(
        session_factory=MagicMock(), redis=MagicMock()
    )
    batch = [
        _valid_finding(title="kept", fingerprint="a" * 64),
        {"tool_name": "nmap", "title": "port 22 open"},  # malformed
    ]

    with caplog.at_level(logging.DEBUG, logger=LOGGER_NAME):
        dicts = consumer._build_finding_dicts(batch)

    assert [d["title"] for d in dicts] == ["kept"]

    details = [r for r in _reject_records(caplog) if r.levelno == logging.WARNING]
    aggregates = [r for r in _reject_records(caplog) if r.levelno == logging.ERROR]

    assert len(details) == 1, "per-finding detail must be at WARNING"
    assert len(aggregates) == 1, "aggregate must be at ERROR"
    # The detail must actually say why, not merely that.
    assert "nmap" in details[0].getMessage()
    assert "1 of 2" in aggregates[0].getMessage()
    # Partial loss is not flagged as total loss.
    assert "ENTIRE BATCH LOST" not in aggregates[0].getMessage()


def test_rejection_detail_is_capped_but_the_count_is_not(caplog):
    """A cross-repo schema mismatch rejects every finding identically.

    642 identical tracebacks would bury the aggregate, so detail is capped
    at 3 — while the aggregate still reports the true total. The total-loss
    case is called out, because that is the nmap shape: job reports
    success, nothing persists.
    """
    consumer = CompletionsConsumer(
        session_factory=MagicMock(), redis=MagicMock()
    )
    batch = [{"tool_name": "nmap", "title": f"port {p}"} for p in range(20)]

    with caplog.at_level(logging.DEBUG, logger=LOGGER_NAME):
        dicts = consumer._build_finding_dicts(batch)

    assert dicts == []
    details = [r for r in _reject_records(caplog) if r.levelno == logging.WARNING]
    aggregates = [r for r in _reject_records(caplog) if r.levelno == logging.ERROR]

    assert len(details) == 3, "detail must be capped at _MAX_REJECTION_DETAILS"
    assert len(aggregates) == 1
    # Capped detail must not cap the truth.
    assert "20 of 20" in aggregates[0].getMessage()
    assert "ENTIRE BATCH LOST" in aggregates[0].getMessage()


# ---------------------------------------------------------------- 5. row fallback


@pytest.mark.asyncio
async def test_engine_and_idempotency_key_fall_back_to_the_job_row(
    scan_with_jobs, fake_redis, session_factory, caplog
):
    """Both fields are ``omitempty`` in the Go ``JobCompletedEvent``, so an
    event may legitimately arrive without them. The ScanJob row always
    has them, and the line must not print ``engine=None``."""
    s = scan_with_jobs
    job = s["jobs"][2]  # sslyze
    event = _event(job, status="failed")
    del event["engine"]
    del event["idempotency_key"]

    consumer = CompletionsConsumer(
        session_factory=session_factory, redis=fake_redis
    )
    with caplog.at_level(logging.INFO, logger=LOGGER_NAME):
        await consumer._handle(event)

    lines = _job_completed_lines(caplog)
    assert len(lines) == 1, "no job_completed line emitted for the failed job"
    rec = lines[0]
    assert rec.engine == "sslyze"
    assert rec.idempotency_key == job.idempotency_key
    assert "engine=sslyze" in rec.getMessage()
    assert f"idempotency_key={job.idempotency_key}" in rec.getMessage()
