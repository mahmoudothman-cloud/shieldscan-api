"""Tests for the run() orchestrator (ADR-030 PY1/PY3/PY4 + Q3 fallback; C2).

End-to-end at the service level via in-memory Qdrant + mocked embeddings:
empty-findings short-circuit, the happy embed→dedup→promote path, the 429
rule-based fingerprint fallback (degraded-but-complete), and error propagation.
"""

from __future__ import annotations

import pytest
from sqlalchemy import func, select

from app.models.ai import AIAPICall
from app.models.vulnerabilities import Vulnerability
from app.services.ai import pipeline as pipeline_mod
from app.services.ai.pipeline import run
from tests.services.ai.conftest import (
    FakeEmbeddings,
    add_raw_finding,
    install_openai,
    install_qdrant,
    make_rate_limit_error,
    seed_org_project_scan,
)


async def _count_vulns(db_session, scan_id):
    return (
        await db_session.execute(
            select(func.count(Vulnerability.id)).where(
                Vulnerability.scan_id == scan_id
            )
        )
    ).scalar_one()


# ---------------------------------------------------------------- PY4 short-circuit


async def test_run_empty_raw_findings_short_circuit(db_session, stub_ai_clients):
    _org, _project, scan = await seed_org_project_scan(db_session)
    await run(db=db_session, scan_id=scan.id)
    # No findings → no embeddings, no Qdrant collection, no Vulnerabilities.
    assert len(stub_ai_clients.openai.calls) == 0
    assert await _count_vulns(db_session, scan.id) == 0


# ---------------------------------------------------------------- happy path


async def test_run_full_pipeline_happy_path(db_session, stub_ai_clients):
    org, _project, scan = await seed_org_project_scan(db_session)
    await add_raw_finding(db_session, scan, org, target_url="https://ai.example.com/a")
    await add_raw_finding(db_session, scan, org, target_url="https://ai.example.com/b")

    await run(db=db_session, scan_id=scan.id)

    # Constant-vector stub → both findings cluster into a single Vulnerability.
    assert await _count_vulns(db_session, scan.id) == 1
    assert len(stub_ai_clients.openai.calls) == 1  # one batch


async def test_run_links_findings_after_outer_flush(db_session, stub_ai_clients):
    """Q7 B.a: run()'s final flush persists the raw_finding link UPDATEs even
    though Vulnerability INSERTs are flushed eagerly (Drift #66 fix)."""
    org, _project, scan = await seed_org_project_scan(db_session)
    finding = await add_raw_finding(db_session, scan, org)
    await run(db=db_session, scan_id=scan.id)
    assert finding.vulnerability_id is not None
    assert finding.promoted_at is not None


async def test_run_derives_project_id_from_scan(db_session, stub_ai_clients):
    org, project, scan = await seed_org_project_scan(db_session)
    await add_raw_finding(db_session, scan, org)
    await run(db=db_session, scan_id=scan.id)
    vuln = (
        await db_session.execute(
            select(Vulnerability).where(Vulnerability.scan_id == scan.id)
        )
    ).scalar_one()
    assert vuln.project_id == project.id


# ---------------------------------------------------------------- Q3 429 fallback


async def test_run_429_rule_based_fingerprint_fallback(db_session, monkeypatch):
    org, _project, scan = await seed_org_project_scan(db_session)
    # Two distinct fingerprints → two fallback Vulnerabilities (no vector dedup).
    await add_raw_finding(db_session, scan, org, fingerprint="a" * 32)
    await add_raw_finding(db_session, scan, org, fingerprint="b" * 32)

    async def _no_sleep(_delay):
        return None

    monkeypatch.setattr(pipeline_mod.asyncio, "sleep", _no_sleep)
    install_openai(monkeypatch, FakeEmbeddings(raise_exc=make_rate_limit_error()))
    install_qdrant(monkeypatch)

    await run(db=db_session, scan_id=scan.id)

    assert scan.ai_pipeline_degraded is True
    # Fallback still promotes (degraded-but-complete; SPEC §8.6 resilience).
    assert await _count_vulns(db_session, scan.id) == 2
    # No embedding cost logged when the batch never succeeds.
    logged = (
        await db_session.execute(
            select(func.count(AIAPICall.id)).where(AIAPICall.scan_id == scan.id)
        )
    ).scalar_one()
    assert logged == 0


async def test_run_429_fallback_clusters_by_exact_fingerprint(db_session, monkeypatch):
    org, _project, scan = await seed_org_project_scan(db_session)
    # Identical fingerprint → fallback collapses to a single Vulnerability.
    await add_raw_finding(db_session, scan, org, fingerprint="c" * 32)
    await add_raw_finding(db_session, scan, org, fingerprint="c" * 32)

    async def _no_sleep(_delay):
        return None

    monkeypatch.setattr(pipeline_mod.asyncio, "sleep", _no_sleep)
    install_openai(monkeypatch, FakeEmbeddings(raise_exc=make_rate_limit_error()))
    install_qdrant(monkeypatch)

    await run(db=db_session, scan_id=scan.id)
    assert await _count_vulns(db_session, scan.id) == 1


# ---------------------------------------------------------------- PY4 propagation


async def test_run_propagates_unrecoverable_errors(db_session, monkeypatch):
    org, _project, scan = await seed_org_project_scan(db_session)
    await add_raw_finding(db_session, scan, org)

    install_openai(monkeypatch, FakeEmbeddings())  # embedding succeeds

    class _BrokenQdrant:
        async def collection_exists(self, *a, **k):
            raise RuntimeError("qdrant unavailable")

    monkeypatch.setattr(pipeline_mod, "get_qdrant_client", lambda: _BrokenQdrant())

    # PY4: run() raises; the AIPipelineConsumer (M9.0 C2) owns the FAILED path.
    with pytest.raises(RuntimeError, match="qdrant unavailable"):
        await run(db=db_session, scan_id=scan.id)


async def test_run_missing_scan_is_noop(db_session, stub_ai_clients):
    from uuid import uuid4

    # Establish the org RLS context (the consumer sets the GUC before run()).
    await seed_org_project_scan(db_session)
    await run(db=db_session, scan_id=uuid4())  # vanished scan → no raise, no work
    assert len(stub_ai_clients.openai.calls) == 0
