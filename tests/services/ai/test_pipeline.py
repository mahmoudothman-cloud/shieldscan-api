"""Tests for the run() orchestrator (ADR-030 PY1/PY3/PY4 + Q3 fallback; C2).

End-to-end at the service level via in-memory Qdrant + mocked embeddings:
empty-findings short-circuit, the happy embed→dedup→promote path, the 429
rule-based fingerprint fallback (degraded-but-complete), and error propagation.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
from sqlalchemy import func, select

from app.models.ai import AIAPICall
from app.models.raw_findings import EngineCategory, Severity
from app.models.vulnerabilities import Vulnerability
from app.services.ai import pipeline as pipeline_mod
from app.services.ai.pipeline import (
    _correlate_vulnerabilities,
    _score_vulnerabilities,
    run,
)
from tests.services.ai.conftest import (
    FakeEmbeddings,
    add_raw_finding,
    install_openai,
    install_qdrant,
    make_rate_limit_error,
    seed_org_project_scan,
)


async def _add_vuln(db_session, scan, project, org, **overrides):
    """Seed one Vulnerability row (M9.B correlation/scoring input)."""
    fields = dict(
        organization_id=org.id,
        project_id=project.id,
        scan_id=scan.id,
        title="Vuln",
        severity=Severity.HIGH,
        finding_type="sqli",
        engine_category=EngineCategory.DAST,
        cwe_id="CWE-89",
        cvss_score=8.0,
        parameter="userid",
        fingerprint=uuid4().hex,
    )
    fields.update(overrides)
    vuln = Vulnerability(**fields)
    db_session.add(vuln)
    await db_session.flush()
    return vuln


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


# ---------------------------------------------------------------- M9.B correlation


async def test_correlate_vulnerabilities_skips_when_single_engine_category_present(
    db_session,
):
    org, project, scan = await seed_org_project_scan(db_session)
    v1 = await _add_vuln(db_session, scan, project, org, engine_category=EngineCategory.DAST)
    v2 = await _add_vuln(db_session, scan, project, org, engine_category=EngineCategory.DAST)
    await _correlate_vulnerabilities(db=db_session, scan_id=scan.id)
    # <2 distinct engine_categories → defensive skip (Q13 C); no cluster assigned.
    assert v1.correlation_cluster_id is None
    assert v2.correlation_cluster_id is None


async def test_correlate_vulnerabilities_skips_when_no_vulnerabilities(db_session):
    _org, _project, scan = await seed_org_project_scan(db_session)
    # No Vulnerabilities seeded → no error, no work.
    await _correlate_vulnerabilities(db=db_session, scan_id=scan.id)
    assert await _count_vulns(db_session, scan.id) == 0


async def test_correlate_two_cross_engine_vulnerabilities_create_cluster(db_session):
    org, project, scan = await seed_org_project_scan(db_session)
    # cwe_exact 0.40 + finding_type 0.30 + parameter 0.15 = 0.85 ≥ 0.75.
    v_dast = await _add_vuln(
        db_session, scan, project, org, engine_category=EngineCategory.DAST
    )
    v_sast = await _add_vuln(
        db_session, scan, project, org, engine_category=EngineCategory.SAST
    )
    await _correlate_vulnerabilities(db=db_session, scan_id=scan.id)
    assert v_dast.correlation_cluster_id is not None
    assert v_dast.correlation_cluster_id == v_sast.correlation_cluster_id
    assert v_dast.corroborated_count == 2
    assert v_sast.corroborated_count == 2


async def test_correlate_three_transitive_cross_engine_cluster(db_session):
    org, project, scan = await seed_org_project_scan(db_session)
    v_dast = await _add_vuln(
        db_session, scan, project, org, engine_category=EngineCategory.DAST
    )
    v_sast = await _add_vuln(
        db_session, scan, project, org, engine_category=EngineCategory.SAST
    )
    v_api = await _add_vuln(
        db_session, scan, project, org, engine_category=EngineCategory.API
    )
    await _correlate_vulnerabilities(db=db_session, scan_id=scan.id)
    # Union-find merges all three (pairwise-correlated) into one cluster.
    clusters = {v_dast.correlation_cluster_id, v_sast.correlation_cluster_id, v_api.correlation_cluster_id}
    assert clusters == {v_dast.correlation_cluster_id}
    assert v_dast.correlation_cluster_id is not None
    assert v_dast.corroborated_count == 3  # 3 distinct engine_categories (Q12)


async def test_correlate_distinct_findings_no_cluster_assignment(db_session):
    org, project, scan = await seed_org_project_scan(db_session)
    # Different CWE (not parent/child) + finding_type + parameter → score 0.0.
    v_dast = await _add_vuln(
        db_session, scan, project, org,
        engine_category=EngineCategory.DAST,
        cwe_id="CWE-89", finding_type="sqli", parameter="userid",
    )
    v_sast = await _add_vuln(
        db_session, scan, project, org,
        engine_category=EngineCategory.SAST,
        cwe_id="CWE-22", finding_type="path_traversal", parameter="filepath",
    )
    await _correlate_vulnerabilities(db=db_session, scan_id=scan.id)
    assert v_dast.correlation_cluster_id is None
    assert v_sast.correlation_cluster_id is None


# ---------------------------------------------------------------- M9.B scoring


async def test_score_vulnerabilities_updates_severity_score_and_severity_enum(
    db_session,
):
    org, project, scan = await seed_org_project_scan(db_session)
    # Single engine, corroborated_count=1 → 8.0 × 1.0 × 1.0 = 8.0 → HIGH.
    vuln = await _add_vuln(db_session, scan, project, org, cvss_score=8.0)
    await _score_vulnerabilities(db=db_session, scan_id=scan.id)
    assert vuln.severity_score == 8.0
    assert vuln.severity == Severity.HIGH


async def test_score_vulnerabilities_corroboration_caps_at_ten(db_session):
    org, project, scan = await seed_org_project_scan(db_session)
    # corroborated_count=2 → 8.0 × 1.3 = 10.4, capped at 10.0 → CRITICAL.
    vuln = await _add_vuln(
        db_session, scan, project, org, cvss_score=8.0, corroborated_count=2
    )
    await _score_vulnerabilities(db=db_session, scan_id=scan.id)
    assert vuln.severity_score == 10.0
    assert vuln.severity == Severity.CRITICAL


async def test_run_full_m9b_pipeline_embed_dedup_correlate_score(
    db_session, monkeypatch
):
    """End-to-end: embed → dedup → correlate → score. Distinct embedding vectors
    keep the DAST + SAST findings as separate Vulnerabilities, which then
    correlate by rule (cwe + finding_type + parameter)."""
    org, project, scan = await seed_org_project_scan(db_session)

    def _distinct_vec(text):
        vec = [0.0] * 1536
        vec[hash(text) % 1536] = 1.0
        return vec

    install_openai(monkeypatch, FakeEmbeddings(vector_for=_distinct_vec))
    install_qdrant(monkeypatch)

    await add_raw_finding(
        db_session, scan, org,
        title="SQLi via DAST", engine_category=EngineCategory.DAST,
        tool_name="sqlmap", cwe_id="CWE-89", finding_type="sqli",
        parameter="userid", target_url="https://ai.example.com/users",
    )
    await add_raw_finding(
        db_session, scan, org,
        title="SQLi via SAST", engine_category=EngineCategory.SAST,
        tool_name="semgrep", cwe_id="CWE-89", finding_type="sqli",
        parameter="userid", code_file="app/users.py",
    )

    await run(db=db_session, scan_id=scan.id)

    vulns = (
        (await db_session.execute(select(Vulnerability).where(Vulnerability.scan_id == scan.id)))
        .scalars()
        .all()
    )
    assert len(vulns) == 2  # distinct vectors → two Vulnerabilities
    cluster_ids = {v.correlation_cluster_id for v in vulns}
    assert len(cluster_ids) == 1 and None not in cluster_ids  # both correlated
    assert all(v.corroborated_count == 2 for v in vulns)
    assert all(v.severity_score is not None and v.severity_score > 0 for v in vulns)
