"""End-to-end tests for the M10.A vulnerability endpoints (Task 10.1; SPEC §6).

Covers all 7 canon operations + ADR-012 cross-tenant-404 + Q2 filter semantics
+ Q4/Q5/Q8 PATCH transition/history/audit wiring + Q7 response-shape locks
(ai_fix_text exclusive to /fix). Fixtures mirror tests/routes/test_projects.py
(JWT + use_org GUC); vulnerability seeding reuses the PY7 cross-directory plain
helper ``add_vulnerability`` from tests/services/ai/conftest.
"""

from __future__ import annotations

from uuid import uuid4

import pytest_asyncio
from sqlalchemy import func, select

from app.models.audit import AuditLog
from app.models.identity import Membership, MembershipRole, Organization, User
from app.models.projects import Project
from app.models.raw_findings import EngineCategory, Severity
from app.models.scans import Scan, ScanStatus, ScanType
from app.models.vulnerabilities import VulnerabilityHistory
from app.services.auth import create_access_token, hash_password
from tests.conftest import use_org
from tests.services.ai.conftest import add_raw_finding, add_vulnerability


@pytest_asyncio.fixture
async def vuln_org(client, db_session):
    """Org A admin + verified project + scan: (org, project, scan, headers)."""
    org = Organization(name="Vuln Org", slug=f"vulnorg-{uuid4().hex[:8]}")
    db_session.add(org)
    await db_session.flush()
    await use_org(db_session, org.id)
    user = User(
        email=f"vuln-{uuid4().hex[:6]}@t.co",
        hashed_password=hash_password("VulnPass-1"),
        full_name="Vuln Admin",
        email_verified=True,
    )
    db_session.add(user)
    await db_session.flush()
    db_session.add(
        Membership(user_id=user.id, organization_id=org.id, role=MembershipRole.ADMIN)
    )
    project = Project(
        organization_id=org.id,
        name="VulnApp",
        target_url="https://vuln.example.com",
        root_domain="example.com",
        domain_verified=True,
    )
    db_session.add(project)
    await db_session.flush()
    scan = Scan(
        organization_id=org.id,
        project_id=project.id,
        scan_type=ScanType.FULL_WEB,
        status=ScanStatus.COMPLETED,
        priority="normal",
        config={},
    )
    db_session.add(scan)
    await db_session.flush()
    await db_session.commit()
    headers = {"Authorization": f"Bearer {create_access_token(sub=str(user.id))}"}
    return org, project, scan, headers


@pytest_asyncio.fixture
async def other_org_headers(db_session):
    """Org B admin headers — for cross-tenant 404 tests."""
    org = Organization(name="Other Vuln Org", slug=f"othervuln-{uuid4().hex[:8]}")
    db_session.add(org)
    await db_session.flush()
    await use_org(db_session, org.id)
    user = User(
        email=f"othervuln-{uuid4().hex[:6]}@t.co",
        hashed_password=hash_password("OtherPass-1"),
        full_name="Other",
        email_verified=True,
    )
    db_session.add(user)
    await db_session.flush()
    db_session.add(
        Membership(user_id=user.id, organization_id=org.id, role=MembershipRole.ADMIN)
    )
    await db_session.commit()
    return {"Authorization": f"Bearer {create_access_token(sub=str(user.id))}"}


async def _seed_vuln(db_session, org, project, scan, **overrides):
    vuln = await add_vulnerability(db_session, scan, org, project, **overrides)
    await db_session.commit()
    return vuln


# ---------------------------------------------------------------- org-wide list


async def test_list_empty_returns_envelope(client, vuln_org):
    org, _p, _s, headers = vuln_org
    r = await client.get(f"/v1/orgs/{org.id}/vulnerabilities", headers=headers)
    assert r.status_code == 200
    body = r.json()
    assert body["items"] == []
    assert body["pagination"]["total"] == 0


async def test_list_default_sort_severity_score_desc(client, db_session, vuln_org):
    org, project, scan, headers = vuln_org
    await _seed_vuln(db_session, org, project, scan, title="low", severity_score=2.0)
    await _seed_vuln(db_session, org, project, scan, title="high", severity_score=9.0)
    await _seed_vuln(db_session, org, project, scan, title="mid", severity_score=5.0)

    r = await client.get(f"/v1/orgs/{org.id}/vulnerabilities", headers=headers)
    assert r.status_code == 200
    titles = [i["title"] for i in r.json()["items"]]
    assert titles == ["high", "mid", "low"]


async def test_list_item_shape(client, db_session, vuln_org):
    org, project, scan, headers = vuln_org
    await _seed_vuln(db_session, org, project, scan)
    r = await client.get(f"/v1/orgs/{org.id}/vulnerabilities", headers=headers)
    item = r.json()["items"][0]
    for key in (
        "id", "title", "severity", "severity_score", "status", "cwe_id",
        "engine_category", "corroborated_count", "scan_id", "created_at",
    ):
        assert key in item
    assert "ai_fix_text" not in item  # Q7: /fix-exclusive
    assert "description" not in item  # detail-only


async def test_list_severity_csv_filter(client, db_session, vuln_org):
    org, project, scan, headers = vuln_org
    await _seed_vuln(db_session, org, project, scan, title="c", severity=Severity.CRITICAL)
    await _seed_vuln(db_session, org, project, scan, title="h", severity=Severity.HIGH)
    await _seed_vuln(db_session, org, project, scan, title="l", severity=Severity.LOW)

    r = await client.get(
        f"/v1/orgs/{org.id}/vulnerabilities?severity=critical,high", headers=headers
    )
    sevs = {i["severity"] for i in r.json()["items"]}
    assert sevs == {"critical", "high"}


async def test_list_invalid_severity_422(client, vuln_org):
    org, _p, _s, headers = vuln_org
    r = await client.get(
        f"/v1/orgs/{org.id}/vulnerabilities?severity=bogus", headers=headers
    )
    assert r.status_code == 422


async def test_list_status_and_engine_category_filters(client, db_session, vuln_org):
    org, project, scan, headers = vuln_org
    await _seed_vuln(
        db_session, org, project, scan, title="dast",
        engine_category=EngineCategory.DAST,
    )
    await _seed_vuln(
        db_session, org, project, scan, title="sast",
        engine_category=EngineCategory.SAST,
    )
    r = await client.get(
        f"/v1/orgs/{org.id}/vulnerabilities?engine_category=sast", headers=headers
    )
    assert [i["title"] for i in r.json()["items"]] == ["sast"]

    r = await client.get(
        f"/v1/orgs/{org.id}/vulnerabilities?status=open", headers=headers
    )
    assert r.json()["pagination"]["total"] == 2  # both seeded OPEN by default


async def test_list_scan_and_project_filters(client, db_session, vuln_org):
    org, project, scan, headers = vuln_org
    await _seed_vuln(db_session, org, project, scan, title="scan1-vuln")
    # A second scan in the same org + project, with its own vuln.
    scan2 = Scan(
        organization_id=org.id, project_id=project.id,
        scan_type=ScanType.FULL_WEB, status=ScanStatus.COMPLETED,
        priority="normal", config={},
    )
    db_session.add(scan2)
    await db_session.flush()
    await _seed_vuln(db_session, org, project, scan2, title="scan2-vuln")

    r = await client.get(
        f"/v1/orgs/{org.id}/vulnerabilities?scan_id={scan2.id}", headers=headers
    )
    assert [i["title"] for i in r.json()["items"]] == ["scan2-vuln"]

    r = await client.get(
        f"/v1/orgs/{org.id}/vulnerabilities?project_id={project.id}", headers=headers
    )
    assert r.json()["pagination"]["total"] == 2


async def test_list_per_page_bound(client, vuln_org):
    org, _p, _s, headers = vuln_org
    r = await client.get(
        f"/v1/orgs/{org.id}/vulnerabilities?per_page=101", headers=headers
    )
    assert r.status_code == 422  # PerPage le=100


async def test_list_cross_tenant_404(client, vuln_org, other_org_headers):
    org, _p, _s, _headers = vuln_org
    r = await client.get(
        f"/v1/orgs/{org.id}/vulnerabilities", headers=other_org_headers
    )
    assert r.status_code == 404


# ---------------------------------------------------------------- per-scan list


async def test_per_scan_list_scoped(client, db_session, vuln_org):
    org, project, scan, headers = vuln_org
    await _seed_vuln(db_session, org, project, scan, title="mine")
    r = await client.get(
        f"/v1/orgs/{org.id}/scans/{scan.id}/vulnerabilities", headers=headers
    )
    assert r.status_code == 200
    assert [i["title"] for i in r.json()["items"]] == ["mine"]


async def test_per_scan_list_unknown_scan_404(client, vuln_org):
    org, _p, _s, headers = vuln_org
    r = await client.get(
        f"/v1/orgs/{org.id}/scans/{uuid4()}/vulnerabilities", headers=headers
    )
    assert r.status_code == 404


# ---------------------------------------------------------------- detail


async def test_detail_full_shape_no_fix_text(client, db_session, vuln_org):
    org, project, scan, headers = vuln_org
    vuln = await _seed_vuln(
        db_session, org, project, scan, ai_fix_text="SECRET FIX TEXT"
    )
    r = await client.get(
        f"/v1/orgs/{org.id}/vulnerabilities/{vuln.id}", headers=headers
    )
    assert r.status_code == 200
    body = r.json()
    for key in ("description", "target_url", "parameter", "updated_at",
                "correlation_cluster_id", "mobile_os"):
        assert key in body
    assert "ai_fix_text" not in body  # Q7 exclusivity
    assert "SECRET FIX TEXT" not in r.text


async def test_detail_unknown_404(client, vuln_org):
    org, _p, _s, headers = vuln_org
    r = await client.get(
        f"/v1/orgs/{org.id}/vulnerabilities/{uuid4()}", headers=headers
    )
    assert r.status_code == 404


async def test_detail_cross_tenant_404(client, db_session, vuln_org, other_org_headers):
    org, project, scan, _headers = vuln_org
    # other_org_headers flipped the session GUC to org B (Gotcha 12) — reset.
    await use_org(db_session, org.id)
    vuln = await _seed_vuln(db_session, org, project, scan)
    r = await client.get(
        f"/v1/orgs/{org.id}/vulnerabilities/{vuln.id}", headers=other_org_headers
    )
    assert r.status_code == 404


# ---------------------------------------------------------------- PATCH


async def _history_count(db_session, vuln_id) -> int:
    return (
        await db_session.execute(
            select(func.count(VulnerabilityHistory.id)).where(
                VulnerabilityHistory.vulnerability_id == vuln_id
            )
        )
    ).scalar_one()


async def test_patch_status_change_writes_history_and_audit(
    client, db_session, vuln_org
):
    org, project, scan, headers = vuln_org
    vuln = await _seed_vuln(db_session, org, project, scan)  # status OPEN default

    r = await client.patch(
        f"/v1/orgs/{org.id}/vulnerabilities/{vuln.id}",
        json={"status": "resolved", "notes": "Fixed in PR #123"},
        headers=headers,
    )
    assert r.status_code == 200
    assert r.json()["status"] == "resolved"

    rows = (
        await db_session.execute(
            select(VulnerabilityHistory).where(
                VulnerabilityHistory.vulnerability_id == vuln.id
            )
        )
    ).scalars().all()
    assert len(rows) == 1
    assert rows[0].from_status.value == "open"
    assert rows[0].to_status.value == "resolved"
    assert rows[0].changed_by is not None
    assert rows[0].notes == "Fixed in PR #123"

    audits = (
        await db_session.execute(
            select(AuditLog).where(
                AuditLog.action == "vulnerability.status_changed",
                AuditLog.resource_id == vuln.id,
            )
        )
    ).scalars().all()
    assert len(audits) == 1


async def test_patch_same_status_noop_no_history(client, db_session, vuln_org):
    org, project, scan, headers = vuln_org
    vuln = await _seed_vuln(db_session, org, project, scan)  # OPEN

    r = await client.patch(
        f"/v1/orgs/{org.id}/vulnerabilities/{vuln.id}",
        json={"status": "open"},
        headers=headers,
    )
    assert r.status_code == 200
    assert await _history_count(db_session, vuln.id) == 0  # Q4 no-op


async def test_patch_invalid_status_422(client, db_session, vuln_org):
    org, project, scan, headers = vuln_org
    vuln = await _seed_vuln(db_session, org, project, scan)
    r = await client.patch(
        f"/v1/orgs/{org.id}/vulnerabilities/{vuln.id}",
        json={"status": "bogus"},
        headers=headers,
    )
    assert r.status_code == 422


async def test_patch_cross_tenant_404(client, db_session, vuln_org, other_org_headers):
    org, project, scan, _headers = vuln_org
    # other_org_headers flipped the session GUC to org B (Gotcha 12) — reset.
    await use_org(db_session, org.id)
    vuln = await _seed_vuln(db_session, org, project, scan)
    r = await client.patch(
        f"/v1/orgs/{org.id}/vulnerabilities/{vuln.id}",
        json={"status": "resolved"},
        headers=other_org_headers,
    )
    assert r.status_code == 404


# ---------------------------------------------------------------- evidence


async def test_evidence_projects_raw_findings(client, db_session, vuln_org):
    org, project, scan, headers = vuln_org
    rf = await add_raw_finding(
        db_session, scan, org, tool_name="semgrep",
        engine_category=EngineCategory.SAST,
        description="d" * 900, code_snippet="s" * 1500,
    )
    vuln = await _seed_vuln(
        db_session, org, project, scan, raw_finding_ids=[rf.id]
    )
    r = await client.get(
        f"/v1/orgs/{org.id}/vulnerabilities/{vuln.id}/evidence", headers=headers
    )
    assert r.status_code == 200
    items = r.json()
    assert len(items) == 1
    assert items[0]["tool_name"] == "semgrep"  # Q2: tool_name lives here
    assert len(items[0]["description"]) <= 501
    assert len(items[0]["code_snippet"]) <= 1001


async def test_evidence_empty_when_no_raw_findings(client, db_session, vuln_org):
    org, project, scan, headers = vuln_org
    vuln = await _seed_vuln(db_session, org, project, scan, raw_finding_ids=None)
    r = await client.get(
        f"/v1/orgs/{org.id}/vulnerabilities/{vuln.id}/evidence", headers=headers
    )
    assert r.status_code == 200
    assert r.json() == []


# ---------------------------------------------------------------- fix


async def test_fix_returns_ai_fix_text(client, db_session, vuln_org):
    org, project, scan, headers = vuln_org
    vuln = await _seed_vuln(
        db_session, org, project, scan, ai_fix_text="## Explanation\nfix it"
    )
    r = await client.get(
        f"/v1/orgs/{org.id}/vulnerabilities/{vuln.id}/fix", headers=headers
    )
    assert r.status_code == 200
    assert r.json()["ai_fix_text"] == "## Explanation\nfix it"
    assert r.json()["is_fallback"] is False

    vuln.ai_fix_is_fallback = True
    await db_session.commit()
    r = await client.get(
        f"/v1/orgs/{org.id}/vulnerabilities/{vuln.id}/fix", headers=headers
    )
    assert r.json()["is_fallback"] is True


async def test_fix_null_when_not_generated(client, db_session, vuln_org):
    org, project, scan, headers = vuln_org
    vuln = await _seed_vuln(db_session, org, project, scan)
    r = await client.get(
        f"/v1/orgs/{org.id}/vulnerabilities/{vuln.id}/fix", headers=headers
    )
    assert r.json()["ai_fix_text"] is None


# ---------------------------------------------------------------- history


async def test_history_newest_first(client, db_session, vuln_org):
    org, project, scan, headers = vuln_org
    vuln = await _seed_vuln(db_session, org, project, scan)

    for target in ("resolved", "open"):
        r = await client.patch(
            f"/v1/orgs/{org.id}/vulnerabilities/{vuln.id}",
            json={"status": target},
            headers=headers,
        )
        assert r.status_code == 200

    r = await client.get(
        f"/v1/orgs/{org.id}/vulnerabilities/{vuln.id}/history", headers=headers
    )
    rows = r.json()
    assert len(rows) == 2
    assert rows[0]["to_status"] == "open"  # newest first
    assert rows[1]["to_status"] == "resolved"


async def test_history_empty_initially(client, db_session, vuln_org):
    org, project, scan, headers = vuln_org
    vuln = await _seed_vuln(db_session, org, project, scan)
    r = await client.get(
        f"/v1/orgs/{org.id}/vulnerabilities/{vuln.id}/history", headers=headers
    )
    assert r.status_code == 200
    assert r.json() == []
