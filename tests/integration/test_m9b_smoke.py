"""M9.B end-to-end smoke (ADR-031 Path B; Stage 3 C3).

Drives correlation + scoring against seeded Vulnerabilities + the full
embed→dedup→correlate→score pipeline, asserting the M9.B outputs:
correlation_cluster_id (Path B link, no row deletion), corroborated_count
(engine-distinct, Q12), severity_score + severity (SPEC §8.3 / Q11), and the
PoC-derived exploitability multiplier (Q10 / PY5 tool_name).
"""

from __future__ import annotations

import pytest
from sqlalchemy import func, select

from app.models.raw_findings import EngineCategory, Severity
from app.models.vulnerabilities import Vulnerability
from app.services.ai.pipeline import (
    _correlate_vulnerabilities,
    _score_vulnerabilities,
    run,
)
from tests.services.ai.conftest import (
    FakeEmbeddings,
    add_raw_finding,
    add_vulnerability,
    install_openai,
    install_qdrant,
    seed_org_project_scan,
)


# Fixtures live next to their consumer — fixtures do not cross sibling conftest
# directories (this smoke file is in tests/integration/, the AI conftest in
# tests/services/ai/). Built on the importable conftest helpers (Q15 B.a).
@pytest.fixture
async def cross_engine_vulnerabilities(db_session):
    """Scan + a DAST/SAST Vulnerability pair (+representative raw_findings) that
    correlate ≥0.75 (cwe_exact 0.40 + finding_type 0.30 + parameter 0.15 = 0.85)."""
    org, project, scan = await seed_org_project_scan(db_session)
    rf_dast = await add_raw_finding(
        db_session, scan, org,
        engine_category=EngineCategory.DAST, tool_name="nuclei",
        cwe_id="CWE-89", finding_type="sqli", parameter="userid",
        target_url="https://example.com/api/users",
    )
    rf_sast = await add_raw_finding(
        db_session, scan, org,
        engine_category=EngineCategory.SAST, tool_name="semgrep",
        cwe_id="CWE-89", finding_type="sqli", parameter="userid",
        code_file="routes/users.py",
        code_snippet="cursor.execute('SELECT * FROM users WHERE id=' + userid)",
    )
    v_dast = await add_vulnerability(
        db_session, scan, org, project,
        engine_category=EngineCategory.DAST, cwe_id="CWE-89",
        finding_type="sqli", parameter="userid",
        target_url="https://example.com/api/users",
        raw_finding_ids=[rf_dast.id],
    )
    v_sast = await add_vulnerability(
        db_session, scan, org, project,
        engine_category=EngineCategory.SAST, cwe_id="CWE-89",
        finding_type="sqli", code_file="routes/users.py",
        raw_finding_ids=[rf_sast.id],
    )
    return scan, [v_dast, v_sast]


@pytest.fixture
async def single_engine_vulnerabilities(db_session):
    """Scan + two same-engine (DAST) Vulnerabilities — exercises the Q13 C
    defensive skip (<2 distinct engine_categories)."""
    org, project, scan = await seed_org_project_scan(db_session)
    v1 = await add_vulnerability(
        db_session, scan, org, project, engine_category=EngineCategory.DAST
    )
    v2 = await add_vulnerability(
        db_session, scan, org, project, engine_category=EngineCategory.DAST
    )
    return scan, [v1, v2]


async def _vulns(db_session, scan_id):
    return (
        (await db_session.execute(select(Vulnerability).where(Vulnerability.scan_id == scan_id)))
        .scalars()
        .all()
    )


# ---------------------------------------------------------------- full pipeline


async def test_m9b_smoke_full_pipeline_cross_engine_correlation_and_scoring(
    db_session, monkeypatch
):
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

    vulns = await _vulns(db_session, scan.id)
    assert len(vulns) == 2  # distinct vectors → two Vulnerabilities (Path C preserved)
    assert len({v.correlation_cluster_id for v in vulns}) == 1
    assert all(v.correlation_cluster_id is not None for v in vulns)
    assert all(v.corroborated_count == 2 for v in vulns)
    assert all(v.severity_score is not None and v.severity_score > 0 for v in vulns)
    assert all(v.severity in set(Severity) for v in vulns)


# ---------------------------------------------------------------- fixtures-driven


async def test_m9b_smoke_single_engine_defensive_skip(
    db_session, single_engine_vulnerabilities
):
    scan, vulns = single_engine_vulnerabilities
    await _correlate_vulnerabilities(db=db_session, scan_id=scan.id)
    # <2 engine_categories → no correlation; Path B leaves rows untouched.
    assert all(v.correlation_cluster_id is None for v in vulns)
    # Scoring still runs regardless of correlation.
    await _score_vulnerabilities(db=db_session, scan_id=scan.id)
    assert all(v.severity_score is not None for v in vulns)


async def test_m9b_smoke_corroborated_count_via_cross_engine_cluster(
    db_session, cross_engine_vulnerabilities
):
    scan, vulns = cross_engine_vulnerabilities
    await _correlate_vulnerabilities(db=db_session, scan_id=scan.id)
    assert len({v.correlation_cluster_id for v in vulns}) == 1
    assert all(v.correlation_cluster_id is not None for v in vulns)
    assert all(v.corroborated_count == 2 for v in vulns)  # Q12 engine-distinct


async def test_m9b_smoke_severity_score_updates_severity_enum(
    db_session, cross_engine_vulnerabilities
):
    scan, vulns = cross_engine_vulnerabilities
    await _correlate_vulnerabilities(db=db_session, scan_id=scan.id)
    await _score_vulnerabilities(db=db_session, scan_id=scan.id)
    # cvss 8.0 × corroboration 1.3 (2 engines) × exploitability ≥1.0 ≥ 10.0 cap.
    for vuln in vulns:
        assert vuln.severity_score == 10.0
        assert vuln.severity == Severity.CRITICAL


# ---------------------------------------------------------------- PoC + Path B


async def test_m9b_smoke_poc_proven_tool_name_exploitability(db_session):
    org, project, scan = await seed_org_project_scan(db_session)
    rf_poc = await add_raw_finding(db_session, scan, org, tool_name="nuclei")
    rf_plain = await add_raw_finding(db_session, scan, org, tool_name="semgrep")
    v_poc = await add_vulnerability(
        db_session, scan, org, project, cvss_score=8.0, raw_finding_ids=[rf_poc.id]
    )
    v_plain = await add_vulnerability(
        db_session, scan, org, project, cvss_score=8.0, raw_finding_ids=[rf_plain.id]
    )
    # Same engine → no correlation; corroboration stays 1.0; isolate exploitability.
    await _score_vulnerabilities(db=db_session, scan_id=scan.id)
    assert v_poc.severity_score == 9.6  # 8.0 × 1.0 × 1.2 (PoC)
    assert v_plain.severity_score == 8.0  # 8.0 × 1.0 × 1.0
    assert v_poc.severity_score > v_plain.severity_score


async def test_m9b_smoke_below_threshold_no_cluster_assignment(db_session):
    org, project, scan = await seed_org_project_scan(db_session)
    await add_vulnerability(
        db_session, scan, org, project,
        engine_category=EngineCategory.DAST,
        cwe_id="CWE-89", finding_type="sqli", parameter="userid",
    )
    await add_vulnerability(
        db_session, scan, org, project,
        engine_category=EngineCategory.SAST,
        cwe_id="CWE-352", finding_type="csrf", parameter="token",
    )
    await _correlate_vulnerabilities(db=db_session, scan_id=scan.id)
    vulns = await _vulns(db_session, scan.id)
    # Below 0.75 → no cluster; both Vulnerabilities preserved (Path B).
    assert len(vulns) == 2
    assert all(v.correlation_cluster_id is None for v in vulns)
    assert (
        await db_session.execute(
            select(func.count(Vulnerability.id)).where(Vulnerability.scan_id == scan.id)
        )
    ).scalar_one() == 2
