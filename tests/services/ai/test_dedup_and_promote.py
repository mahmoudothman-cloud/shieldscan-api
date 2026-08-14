"""Tests for the dedup + Path C promotion stage (ADR-030 Q5/Q6/Q7; C2).

Covers per-scan vector dedup, first-emitted cluster representative promotion,
evidence merge (append-only + idempotent), the PY2 project_id derivation, and
the Drift #66 FK-ordering regression-guard. Qdrant runs in-memory (Q9 B.a) for
real cosine behavior; embedding vectors are supplied directly so clustering is
deterministic.
"""

from __future__ import annotations

from sqlalchemy import func, select

from app.config import settings
from app.models.vulnerabilities import Vulnerability
from app.services.ai.pipeline import (
    _collection_name,
    _create_vulnerability_from_finding,
    _dedup_and_promote,
    _ensure_collection_exists,
    _merge_evidence,
)
from app.services.ai.promotion_denylist import denylisted_plugin_ids
from tests.services.ai.conftest import (
    add_raw_finding,
    seed_org_project_scan,
)

# Two unit vectors: identical → cosine 1.0 (cluster); orthogonal → 0.0 (distinct).
_VEC_A = [1.0] + [0.0] * 1535
_VEC_B = [0.0, 1.0] + [0.0] * 1534


async def _count_vulns(db_session, scan_id):
    return (
        await db_session.execute(
            select(func.count(Vulnerability.id)).where(
                Vulnerability.scan_id == scan_id
            )
        )
    ).scalar_one()


# ---------------------------------------------------------------- defensive


async def test_dedup_and_promote_empty_raw_findings_is_noop(db_session, stub_qdrant):
    _org, _project, scan = await seed_org_project_scan(db_session)
    await _dedup_and_promote(
        db=db_session, scan=scan, raw_findings=[], embeddings={}
    )
    await db_session.flush()
    assert await _count_vulns(db_session, scan.id) == 0


# ---------------------------------------------------------------- promotion (Path C)


async def test_single_finding_creates_new_vulnerability(db_session, stub_qdrant):
    org, _project, scan = await seed_org_project_scan(db_session)
    finding = await add_raw_finding(db_session, scan, org)
    await _dedup_and_promote(
        db=db_session,
        scan=scan,
        raw_findings=[finding],
        embeddings={finding.id: _VEC_A},
    )
    await db_session.flush()
    assert await _count_vulns(db_session, scan.id) == 1


async def test_two_clustering_findings_create_one_vulnerability(
    db_session, stub_qdrant
):
    org, _project, scan = await seed_org_project_scan(db_session)
    f1 = await add_raw_finding(db_session, scan, org, title="XSS one")
    f2 = await add_raw_finding(db_session, scan, org, title="XSS two")
    await _dedup_and_promote(
        db=db_session,
        scan=scan,
        raw_findings=[f1, f2],
        embeddings={f1.id: _VEC_A, f2.id: _VEC_A},  # identical → cluster
    )
    await db_session.flush()

    assert await _count_vulns(db_session, scan.id) == 1
    vuln = (
        await db_session.execute(
            select(Vulnerability).where(Vulnerability.scan_id == scan.id)
        )
    ).scalar_one()
    assert set(vuln.raw_finding_ids) == {f1.id, f2.id}


async def test_two_distinct_findings_create_two_vulnerabilities(
    db_session, stub_qdrant
):
    org, _project, scan = await seed_org_project_scan(db_session)
    f1 = await add_raw_finding(
        db_session, scan, org, target_url="https://ai.example.com/users"
    )
    f2 = await add_raw_finding(
        db_session, scan, org, target_url="https://ai.example.com/products"
    )
    await _dedup_and_promote(
        db=db_session,
        scan=scan,
        raw_findings=[f1, f2],
        embeddings={f1.id: _VEC_A, f2.id: _VEC_B},  # orthogonal → distinct
    )
    await db_session.flush()
    assert await _count_vulns(db_session, scan.id) == 2


# ---------------------------------------------------------------- Qdrant collection (Q5)


async def test_qdrant_collection_created_lazily(db_session, stub_qdrant):
    org, _project, scan = await seed_org_project_scan(db_session)
    collection = _collection_name(scan.organization_id)
    assert await stub_qdrant.collection_exists(collection) is False

    finding = await add_raw_finding(db_session, scan, org)
    await _dedup_and_promote(
        db=db_session,
        scan=scan,
        raw_findings=[finding],
        embeddings={finding.id: _VEC_A},
    )
    assert await stub_qdrant.collection_exists(collection) is True


async def test_ensure_collection_idempotent(db_session, stub_qdrant):
    _org, _project, scan = await seed_org_project_scan(db_session)
    collection = _collection_name(scan.organization_id)
    await _ensure_collection_exists(stub_qdrant, collection)
    await _ensure_collection_exists(stub_qdrant, collection)  # no error on re-run
    assert await stub_qdrant.collection_exists(collection) is True


# ---------------------------------------------------------------- state-transition (Q6 B.a)


async def test_raw_finding_promotion_state_set(db_session, stub_qdrant):
    org, _project, scan = await seed_org_project_scan(db_session)
    finding = await add_raw_finding(db_session, scan, org)
    await _dedup_and_promote(
        db=db_session,
        scan=scan,
        raw_findings=[finding],
        embeddings={finding.id: _VEC_A},
    )
    await db_session.flush()
    vuln = (
        await db_session.execute(
            select(Vulnerability).where(Vulnerability.scan_id == scan.id)
        )
    ).scalar_one()
    assert finding.promoted_at is not None
    assert finding.vulnerability_id == vuln.id


# ---------------------------------------------------------------- merge_evidence (Q7)


async def test_merge_evidence_appends_raw_finding_id(db_session, stub_qdrant):
    org, _project, scan = await seed_org_project_scan(db_session)
    f1 = await add_raw_finding(db_session, scan, org)
    f2 = await add_raw_finding(db_session, scan, org)
    vuln = await _create_vulnerability_from_finding(
        db=db_session, scan=scan, finding=f1, point_id=None
    )
    await _merge_evidence(db=db_session, vulnerability=vuln, raw_finding=f2)
    await db_session.flush()

    assert vuln.raw_finding_ids == [f1.id, f2.id]
    assert f2.vulnerability_id == vuln.id
    assert f2.promoted_at is not None


async def test_merge_evidence_idempotent(db_session, stub_qdrant):
    org, _project, scan = await seed_org_project_scan(db_session)
    f1 = await add_raw_finding(db_session, scan, org)
    f2 = await add_raw_finding(db_session, scan, org)
    vuln = await _create_vulnerability_from_finding(
        db=db_session, scan=scan, finding=f1, point_id=None
    )
    await _merge_evidence(db=db_session, vulnerability=vuln, raw_finding=f2)
    await _merge_evidence(db=db_session, vulnerability=vuln, raw_finding=f2)  # again
    await db_session.flush()
    assert vuln.raw_finding_ids == [f1.id, f2.id]  # no duplicate append


# ---------------------------------------------------------------- PY2 + Drift #66


async def test_vulnerability_project_id_derived_from_scan(db_session, stub_qdrant):
    """PY2 / V-NNE: RawFinding has no project_id; it is derived from the Scan."""
    org, project, scan = await seed_org_project_scan(db_session)
    finding = await add_raw_finding(db_session, scan, org)
    assert not hasattr(finding, "project_id") or getattr(finding, "project_id", None) is None
    vuln = await _create_vulnerability_from_finding(
        db=db_session, scan=scan, finding=finding, point_id=None
    )
    assert vuln.project_id == scan.project_id == project.id


async def test_drift_66_fk_ordering_regression_guard(db_session, stub_qdrant):
    """Drift #66 guard: the Vulnerability INSERT must be flushed before the
    raw_finding FK link, else ``raw_findings.vulnerability_id`` violates its FK.

    The Vulnerability row being queryable immediately after the call (before any
    outer commit) proves the intermediate flush happened; the final flush of the
    raw_finding UPDATE then resolves cleanly.
    """
    org, _project, scan = await seed_org_project_scan(db_session)
    finding = await add_raw_finding(db_session, scan, org)

    vuln = await _create_vulnerability_from_finding(
        db=db_session, scan=scan, finding=finding, point_id=None
    )
    # Persisted by the intermediate flush — visible without an outer commit.
    persisted = (
        await db_session.execute(
            select(Vulnerability).where(Vulnerability.id == vuln.id)
        )
    ).scalar_one_or_none()
    assert persisted is not None

    # The deferred raw_finding UPDATE resolves its FK at the final flush.
    await db_session.flush()
    assert finding.vulnerability_id == vuln.id


async def test_cluster_representative_fields_populated(db_session, stub_qdrant):
    org, _project, scan = await seed_org_project_scan(
        db_session,
    )
    finding = await add_raw_finding(
        db_session,
        scan,
        org,
        title="CSRF",
        finding_type="csrf",
        cwe_id="CWE-352",
        target_url="https://ai.example.com/transfer",
    )
    vuln = await _create_vulnerability_from_finding(
        db=db_session, scan=scan, finding=finding, point_id=None
    )
    assert vuln.title == finding.title
    assert vuln.severity == finding.severity
    assert vuln.finding_type == finding.finding_type
    assert vuln.engine_category == finding.engine_category
    assert vuln.target_url == finding.target_url
    assert vuln.cwe_id == finding.cwe_id
    assert vuln.fingerprint == finding.fingerprint
    assert vuln.raw_finding_ids == [finding.id]


# ------------------------------------------------- promotion denylist (config)


async def test_denylisted_plugin_id_is_not_promoted(
    db_session, stub_qdrant, monkeypatch
):
    """A denylisted plugin id yields no Vulnerability — but the raw finding stays.

    ZAP 10109 "Modern Web Application" is an advisory that the target is a SPA,
    not a finding: 74 raw findings on one live scan. It is filtered at PROMOTION
    so raw_findings remains the complete 90-day audit record (SPEC §5.4).
    """
    monkeypatch.setattr(settings, "PROMOTION_DENYLIST_PLUGIN_IDS", "10109")
    org, _project, scan = await seed_org_project_scan(db_session)
    finding = await add_raw_finding(
        db_session, scan, org, tool_metadata={"plugin_id": "10109"}
    )
    await _dedup_and_promote(
        db=db_session,
        scan=scan,
        raw_findings=[finding],
        embeddings={finding.id: _VEC_A},
    )
    await db_session.flush()

    assert await _count_vulns(db_session, scan.id) == 0
    # The audit record is untouched: still present, never marked promoted.
    assert finding.vulnerability_id is None
    assert finding.promoted_at is None


async def test_non_denylisted_plugin_id_still_promotes(
    db_session, stub_qdrant, monkeypatch
):
    monkeypatch.setattr(settings, "PROMOTION_DENYLIST_PLUGIN_IDS", "10109")
    org, _project, scan = await seed_org_project_scan(db_session)
    finding = await add_raw_finding(
        db_session, scan, org, tool_metadata={"plugin_id": "10038"}
    )
    await _dedup_and_promote(
        db=db_session,
        scan=scan,
        raw_findings=[finding],
        embeddings={finding.id: _VEC_A},
    )
    await db_session.flush()
    assert await _count_vulns(db_session, scan.id) == 1


async def test_finding_without_plugin_id_metadata_still_promotes(
    db_session, stub_qdrant, monkeypatch
):
    """Absence of the key is not a match — most tools emit no plugin_id at all."""
    monkeypatch.setattr(settings, "PROMOTION_DENYLIST_PLUGIN_IDS", "10109")
    org, _project, scan = await seed_org_project_scan(db_session)
    finding = await add_raw_finding(db_session, scan, org, tool_metadata=None)
    await _dedup_and_promote(
        db=db_session,
        scan=scan,
        raw_findings=[finding],
        embeddings={finding.id: _VEC_A},
    )
    await db_session.flush()
    assert await _count_vulns(db_session, scan.id) == 1


async def test_empty_denylist_config_disables_the_filter(
    db_session, stub_qdrant, monkeypatch
):
    monkeypatch.setattr(settings, "PROMOTION_DENYLIST_PLUGIN_IDS", "")
    org, _project, scan = await seed_org_project_scan(db_session)
    finding = await add_raw_finding(
        db_session, scan, org, tool_metadata={"plugin_id": "10109"}
    )
    await _dedup_and_promote(
        db=db_session,
        scan=scan,
        raw_findings=[finding],
        embeddings={finding.id: _VEC_A},
    )
    await db_session.flush()
    assert await _count_vulns(db_session, scan.id) == 1


def test_denylist_config_parses_comma_separated_list(monkeypatch):
    monkeypatch.setattr(
        settings, "PROMOTION_DENYLIST_PLUGIN_IDS", "10109, 10096 ,,90022"
    )
    assert denylisted_plugin_ids() == {"10109", "10096", "90022"}
