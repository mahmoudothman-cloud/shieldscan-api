"""End-to-end orchestrator smoke tests for M9.D (ADR-033; Q4 both-paths).

Drives ``AIPipelineConsumer._process`` directly (the established pattern from
tests/services/test_ai_pipeline_consumer.py) and asserts the C1 terminal-metadata
wiring end-to-end: ``completed_at`` stamped at every consumer terminal transition
(COMPLETED / PARTIAL / FAILED) + ``error_message`` populated on PARTIAL/FAILED and
null on COMPLETED. Helpers are imported as plain functions from the AI conftest;
fixtures do not cross sibling conftest directories (PY7; M9.B C3 lesson) — the
``fake_redis`` + ``session_factory`` fixtures live in the root tests/conftest.py.
"""

from __future__ import annotations

from uuid import uuid4

from sqlalchemy import select

from app.models.identity import Organization
from app.models.projects import Project
from app.models.raw_findings import EngineCategory
from app.models.scans import Scan, ScanJob, ScanStatus, ScanType
from app.services import ai_pipeline_consumer as consumer_mod
from app.services.ai_pipeline_consumer import AIPipelineConsumer
from app.db.tenant_context import set_tenant_context
from tests.conftest import use_org
from tests.services.ai.conftest import (
    FakeEmbeddings,
    add_raw_finding,
    install_anthropic,
    install_openai,
    install_qdrant,
    make_anthropic_response,
)

_FIX = "## Explanation\na\n## Fix Code\nb\n## Remediation Steps\n1. c"
_SUMMARY = (
    "## Executive Summary\na\n## Key Findings\nb\n## Risk Posture\nc\n"
    "## Recommended Actions\n1. d"
)


def _distinct_vec(t):
    vec = [0.0] * 1536
    vec[hash(t) % 1536] = 1.0
    return vec


async def _seed_analyzing_scan(db_session, *, job_statuses=("completed",)):
    """Org + project + an ANALYZING scan + sibling ScanJobs (committed)."""
    org = Organization(name="M9D Org", slug=f"m9d-{uuid4().hex[:8]}")
    db_session.add(org)
    await db_session.flush()
    await use_org(db_session, org.id)
    project = Project(
        organization_id=org.id,
        name="M9DApp",
        target_url="https://m9d.example.com",
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
                target_url="https://m9d.example.com",
                status=st,
                finding_count=1,
                idempotency_key=f"{scan.id}:tool{i}:1",
            )
        )
    return org, scan


async def _commit_seed(db_session):
    await db_session.commit()


def _payload(org, scan):
    return {"scan_id": str(scan.id), "organization_id": str(org.id)}


async def _read_scan(session_factory, org_id, scan_id):
    async with session_factory() as fresh:
        await set_tenant_context(fresh, org_id)
        return (
            await fresh.execute(select(Scan).where(Scan.id == scan_id))
        ).scalar_one()


async def test_m9d_smoke_completed_terminal_metadata(
    db_session, fake_redis, session_factory, monkeypatch
):
    """Happy path: full 6-stage pipeline → COMPLETED + completed_at +
    executive_summary present + error_message null."""
    org, scan = await _seed_analyzing_scan(db_session, job_statuses=("completed",))
    await add_raw_finding(
        db_session, scan, org,
        title="SQLi", engine_category=EngineCategory.DAST, tool_name="sqlmap",
        cwe_id="CWE-89", finding_type="sqli", parameter="userid",
        target_url="https://m9d.example.com/users",
    )
    await add_raw_finding(
        db_session, scan, org,
        title="XSS", engine_category=EngineCategory.DAST, tool_name="nuclei",
        cwe_id="CWE-79", finding_type="xss", parameter="q",
        target_url="https://m9d.example.com/search",
    )
    await _commit_seed(db_session)
    install_openai(monkeypatch, FakeEmbeddings(vector_for=_distinct_vec))
    install_qdrant(monkeypatch)
    install_anthropic(
        monkeypatch,
        [make_anthropic_response(_FIX), make_anthropic_response(_FIX),
         make_anthropic_response(_SUMMARY)],
    )

    c = AIPipelineConsumer(session_factory=session_factory, redis=fake_redis)
    await c._process(_payload(org, scan))

    fresh = await _read_scan(session_factory, org.id, scan.id)
    assert fresh.status == ScanStatus.COMPLETED
    assert fresh.completed_at is not None
    assert fresh.executive_summary == _SUMMARY
    assert fresh.error_message is None


async def test_m9d_smoke_partial_terminal_metadata(
    db_session, fake_redis, session_factory
):
    """Failure path PARTIAL: ≥1 sibling job failed → PARTIAL + completed_at +
    the exact C1 job-failure summary (no raw_findings; run() short-circuits)."""
    org, scan = await _seed_analyzing_scan(
        db_session, job_statuses=("completed", "failed")
    )
    await _commit_seed(db_session)

    c = AIPipelineConsumer(session_factory=session_factory, redis=fake_redis)
    await c._process(_payload(org, scan))

    fresh = await _read_scan(session_factory, org.id, scan.id)
    assert fresh.status == ScanStatus.PARTIAL
    assert fresh.completed_at is not None
    assert fresh.error_message == (
        "1 of 2 scan jobs failed; partial results available"
    )


async def test_m9d_smoke_failed_terminal_metadata(
    db_session, fake_redis, session_factory, monkeypatch
):
    """Failure path FAILED: pipeline crash → FAILED + completed_at +
    error_message carries the exception text (V-EEC threading) + degraded."""
    org, scan = await _seed_analyzing_scan(db_session, job_statuses=("completed",))
    await _commit_seed(db_session)

    async def _boom(*, db, scan_id):
        raise RuntimeError("pipeline blew up")

    monkeypatch.setattr(consumer_mod, "run", _boom)

    c = AIPipelineConsumer(session_factory=session_factory, redis=fake_redis)
    await c._process(_payload(org, scan))

    fresh = await _read_scan(session_factory, org.id, scan.id)
    assert fresh.status == ScanStatus.FAILED
    assert fresh.completed_at is not None
    assert "pipeline blew up" in fresh.error_message
    assert fresh.ai_pipeline_degraded is True


async def test_m9d_smoke_zero_findings_completed_at_invariant(
    db_session, fake_redis, session_factory
):
    """Zero-findings no-op path: still a consumer terminal transition —
    COMPLETED + completed_at stamped (Q1 invariant) + error_message null."""
    org, scan = await _seed_analyzing_scan(db_session, job_statuses=("completed",))
    await _commit_seed(db_session)

    c = AIPipelineConsumer(session_factory=session_factory, redis=fake_redis)
    await c._process(_payload(org, scan))

    fresh = await _read_scan(session_factory, org.id, scan.id)
    assert fresh.status == ScanStatus.COMPLETED
    assert fresh.completed_at is not None  # Q1: terminal ⟹ stamped
    assert fresh.error_message is None
