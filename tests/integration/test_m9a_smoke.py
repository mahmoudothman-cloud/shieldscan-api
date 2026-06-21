"""M9.A end-to-end smoke (ADR-030 Path C; Stage 3 C2).

Drives the real embed+dedup pipeline through the live consumers + the Task 8.3β
attack-surface endpoint, proving:
  - completions → dispatch → AI consumer → real pipeline → Vulnerabilities → COMPLETED
  - Y2 forward-pin activation: vulnerability_count is non-zero once the pipeline
    populates the vulnerabilities table (pre-M9 it was 0)
  - DQ3 empty-findings short-circuit is preserved (no pipeline, no vulns)
  - clustering collapses similar findings to one Vulnerability per cluster

OpenAI embeddings are mocked + Qdrant runs in-memory (Q9); a constant stub
vector makes any two findings cluster.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import uuid4

import pytest
from qdrant_client import AsyncQdrantClient
from sqlalchemy import func, select
from sqlalchemy.sql import text

from app.models.audit import AuditLog
from app.models.identity import Membership, MembershipRole, Organization, User
from app.models.projects import Project
from app.models.raw_findings import EngineCategory, RawFinding, Severity
from app.models.recon import AttackSurface, SubdomainStatus
from app.models.scans import Scan, ScanJob, ScanStatus, ScanType
from app.models.vulnerabilities import Vulnerability
from app.services.ai import pipeline as pipeline_mod
from app.services.ai.pipeline import run
from app.services.ai_pipeline_consumer import AIPipelineConsumer
from app.services.audit import ScanAction
from app.services.auth import create_access_token, hash_password
from app.services.completions_consumer import CompletionsConsumer
from tests.conftest import use_org


@pytest.fixture
def stub_ai_clients(monkeypatch):
    """Mock OpenAI embeddings (constant vector) + in-memory Qdrant for run()."""

    class _Embeddings:
        async def create(self, *, model, input):
            return SimpleNamespace(
                data=[SimpleNamespace(embedding=[0.1] * 1536) for _ in input],
                usage=SimpleNamespace(prompt_tokens=8),
            )

    monkeypatch.setattr(
        pipeline_mod,
        "get_openai_client",
        lambda: SimpleNamespace(embeddings=_Embeddings()),
    )
    qdrant = AsyncQdrantClient(location=":memory:")
    monkeypatch.setattr(pipeline_mod, "get_qdrant_client", lambda: qdrant)


# ---------------------------------------------------------------- seeding


async def _seed(db_session, *, job_statuses, n_findings, finding_url=None):
    org = Organization(name="M9A Org", slug=f"m9a-{uuid4().hex[:8]}")
    db_session.add(org)
    await db_session.flush()
    await use_org(db_session, org.id)
    project = Project(
        organization_id=org.id,
        name="M9AApp",
        target_url="https://m9a.example.com",
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
            target_url="https://m9a.example.com",
            status="running",
            idempotency_key=f"{scan.id}:tool{i}:1",
        )
        db_session.add(job)
        jobs.append(job)
    for i in range(n_findings):
        db_session.add(
            RawFinding(
                organization_id=org.id,
                scan_id=scan.id,
                tool_name="nuclei",
                engine_category=EngineCategory.DAST,
                title=f"XSS {i}",
                severity=Severity.HIGH,
                finding_type="xss",
                target_url=finding_url or "https://m9a.example.com",
                fingerprint=uuid4().hex,
                discovered_at=datetime.now(timezone.utc),
            )
        )
    await db_session.commit()
    return org, project, scan, jobs


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
        "timestamp": "2026-06-21T12:00:00Z",
    }


async def _scan_status(session_factory, org_id, scan_id):
    async with session_factory() as fresh:
        await fresh.execute(text(f"SET app.current_org_id = '{org_id}'"))
        return (
            (await fresh.execute(select(Scan).where(Scan.id == scan_id)))
            .scalar_one()
            .status
        )


async def _vulns(session_factory, org_id, scan_id):
    async with session_factory() as fresh:
        await fresh.execute(text(f"SET app.current_org_id = '{org_id}'"))
        return (
            (
                await fresh.execute(
                    select(Vulnerability).where(Vulnerability.scan_id == scan_id)
                )
            )
            .scalars()
            .all()
        )


async def _audit_actions(session_factory, org_id, scan_id):
    async with session_factory() as fresh:
        await fresh.execute(text(f"SET app.current_org_id = '{org_id}'"))
        return set(
            (
                await fresh.execute(
                    select(AuditLog.action).where(AuditLog.resource_id == scan_id)
                )
            )
            .scalars()
            .all()
        )


# ---------------------------------------------------------------- e2e happy path


async def test_m9a_smoke_completions_to_completed_with_real_pipeline(
    db_session, fake_redis, session_factory, stub_ai_clients
):
    org, _project, scan, jobs = await _seed(
        db_session, job_statuses=("completed", "completed"), n_findings=2
    )
    completions = CompletionsConsumer(session_factory=session_factory, redis=fake_redis)
    for job in jobs:
        await completions._handle(_completion_event(job, org.id))

    assert await _scan_status(session_factory, org.id, scan.id) == ScanStatus.ANALYZING
    msg = await fake_redis.brpop(AIPipelineConsumer.QUEUE, timeout=1)
    assert msg is not None

    ai_consumer = AIPipelineConsumer(session_factory=session_factory, redis=fake_redis)
    await ai_consumer._process(json.loads(msg[1]))

    assert await _scan_status(session_factory, org.id, scan.id) == ScanStatus.COMPLETED
    actions = await _audit_actions(session_factory, org.id, scan.id)
    assert ScanAction.SCAN_DISPATCHED_AI_PIPELINE.value in actions
    assert ScanAction.SCAN_COMPLETED.value in actions
    # Path C: the pipeline populated the vulnerabilities table.
    assert len(await _vulns(session_factory, org.id, scan.id)) >= 1


# ---------------------------------------------------------------- DQ3 short-circuit


async def test_m9a_smoke_empty_findings_dq3_path(
    db_session, fake_redis, session_factory
):
    org, _project, scan, jobs = await _seed(
        db_session, job_statuses=("completed",), n_findings=0
    )
    completions = CompletionsConsumer(session_factory=session_factory, redis=fake_redis)
    for job in jobs:
        await completions._handle(_completion_event(job, org.id))

    assert await _scan_status(session_factory, org.id, scan.id) == ScanStatus.COMPLETED
    actions = await _audit_actions(session_factory, org.id, scan.id)
    assert ScanAction.SCAN_DISPATCHED_AI_PIPELINE.value not in actions
    assert await fake_redis.brpop(AIPipelineConsumer.QUEUE, timeout=1) is None
    assert len(await _vulns(session_factory, org.id, scan.id)) == 0


# ---------------------------------------------------------------- clustering


async def test_m9a_smoke_clustering_yields_one_vulnerability_per_cluster(
    db_session, fake_redis, session_factory, stub_ai_clients
):
    org, _project, scan, _jobs = await _seed(
        db_session, job_statuses=("completed",), n_findings=2
    )
    # Move directly to the AI phase (the completions path is covered above).
    async with session_factory() as s:
        await s.execute(text(f"SET app.current_org_id = '{org.id}'"))
        sc = (await s.execute(select(Scan).where(Scan.id == scan.id))).scalar_one()
        sc.status = ScanStatus.ANALYZING
        await s.commit()

    ai_consumer = AIPipelineConsumer(session_factory=session_factory, redis=fake_redis)
    await ai_consumer._process(
        {"scan_id": str(scan.id), "organization_id": str(org.id)}
    )

    vulns = await _vulns(session_factory, org.id, scan.id)
    assert len(vulns) == 1  # constant stub vector → single cluster
    assert len(vulns[0].raw_finding_ids) == 2


# ---------------------------------------------------------------- Y2 activation (HTTP)


async def test_m9a_smoke_y2_vulnerability_count_activation(
    db_session, client, stub_ai_clients
):
    """Y2 Task 8.3β forward-pin: the attack-surface endpoint's
    vulnerability_count goes non-zero once the real pipeline promotes a
    Vulnerability whose target_url matches a discovered subdomain."""
    url = "https://api.m9a.example.com"
    org = Organization(name="Y2 Org", slug=f"y2-{uuid4().hex[:8]}")
    db_session.add(org)
    await db_session.flush()
    await use_org(db_session, org.id)
    user = User(
        email=f"y2-{uuid4().hex[:6]}@t.co",
        hashed_password=hash_password("Y2Pass-1"),
        full_name="Y2",
        email_verified=True,
    )
    db_session.add(user)
    await db_session.flush()
    db_session.add(
        Membership(user_id=user.id, organization_id=org.id, role=MembershipRole.ADMIN)
    )
    project = Project(
        organization_id=org.id,
        name="Y2App",
        target_url="https://m9a.example.com",
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
    db_session.add(
        AttackSurface(
            organization_id=org.id,
            scan_id=scan.id,
            root_domain="example.com",
            subdomain="api.m9a.example.com",
            full_url=url,
            status=SubdomainStatus.LIVE,
            status_code=200,
        )
    )
    db_session.add(
        RawFinding(
            organization_id=org.id,
            scan_id=scan.id,
            tool_name="nuclei",
            engine_category=EngineCategory.DAST,
            title="XSS",
            severity=Severity.HIGH,
            finding_type="xss",
            target_url=url,  # matches the AttackSurface.full_url (Y2 join key)
            fingerprint=uuid4().hex,
            discovered_at=datetime.now(timezone.utc),
        )
    )
    await db_session.commit()

    # Real pipeline promotes the finding → a Vulnerability on the same target_url.
    await run(db=db_session, scan_id=scan.id)
    await db_session.commit()

    promoted = (
        await db_session.execute(
            select(func.count(Vulnerability.id)).where(Vulnerability.scan_id == scan.id)
        )
    ).scalar_one()
    assert promoted == 1

    headers = {"Authorization": f"Bearer {create_access_token(sub=str(user.id))}"}
    resp = await client.get(
        f"/v1/orgs/{org.id}/scans/{scan.id}/attack-surface", headers=headers
    )
    assert resp.status_code == 200
    body = resp.json()
    by_url = {entry["url"]: entry for entry in body["subdomains"]}
    assert by_url[url]["vulnerability_count"] == 1  # pre-M9 this was 0
