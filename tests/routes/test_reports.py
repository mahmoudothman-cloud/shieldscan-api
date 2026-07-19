"""End-to-end tests for the M10.B report endpoints (Task 10.4; SPEC §6).

Covers the 5 scan-scoped report routes + G4-L14 409 non-terminal + ADR-012
cross-tenant-404 + G2 presigned PDF delivery + route-layer idempotency.
Fixtures mirror tests/routes/test_vulnerabilities.py (JWT + use_org GUC);
R2 put_object + generate_presigned_get_url are monkeypatch-stubbed at their
consuming modules (the C3 pattern).
"""

from __future__ import annotations

from uuid import uuid4

import jsonschema
import pytest
import pytest_asyncio

import app.routes.reports as reports_module
import app.services.reports.pdf as pdf_module
from app.models.identity import Membership, MembershipRole, Organization, User
from app.models.projects import Project
from app.models.raw_findings import Severity
from app.models.scans import Scan, ScanStatus, ScanType
from app.services.auth import create_access_token, hash_password
from app.services.reports.sarif import _sarif_schema
from tests.conftest import use_org
from tests.services.ai.conftest import add_vulnerability

_EXEC_SUMMARY = "Two findings; one critical SQLi requires immediate attention."


@pytest_asyncio.fixture
async def report_org(client, db_session):
    """Org A admin + project + COMPLETED scan (with summary): (org, project, scan, headers)."""
    org = Organization(name="Report Org", slug=f"rptorg-{uuid4().hex[:8]}")
    db_session.add(org)
    await db_session.flush()
    await use_org(db_session, org.id)
    user = User(
        email=f"rpt-{uuid4().hex[:6]}@t.co",
        hashed_password=hash_password("RptPass-1"),
        full_name="Report Admin",
        email_verified=True,
    )
    db_session.add(user)
    await db_session.flush()
    db_session.add(
        Membership(user_id=user.id, organization_id=org.id, role=MembershipRole.ADMIN)
    )
    project = Project(
        organization_id=org.id,
        name="ReportApp",
        target_url="https://report.example.com",
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
        executive_summary=_EXEC_SUMMARY,
    )
    db_session.add(scan)
    await db_session.commit()
    headers = {"Authorization": f"Bearer {create_access_token(sub=str(user.id))}"}
    return org, project, scan, headers


@pytest_asyncio.fixture
async def other_org_headers(db_session):
    """Org B admin headers — for cross-tenant 404 tests."""
    org = Organization(name="Other Report Org", slug=f"otherrpt-{uuid4().hex[:8]}")
    db_session.add(org)
    await db_session.flush()
    await use_org(db_session, org.id)
    user = User(
        email=f"otherrpt-{uuid4().hex[:6]}@t.co",
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


@pytest.fixture
def stub_r2(monkeypatch):
    """Stub R2 put_object (pdf module) + generate_presigned_get_url (reports module)."""
    puts: list[tuple[str, bytes, str]] = []
    presigns: list[tuple[str, int]] = []

    async def _fake_put(key, content, content_type):
        puts.append((key, content, content_type))

    async def _fake_presign(r2_key, expiry=600):
        presigns.append((r2_key, expiry))
        return f"https://r2.example.test/{r2_key}?sig=deadbeef&exp={expiry}"

    monkeypatch.setattr(pdf_module, "put_object", _fake_put)
    monkeypatch.setattr(reports_module, "generate_presigned_get_url", _fake_presign)
    return {"puts": puts, "presigns": presigns}


async def _seed_vuln(db_session, org, project, scan, **overrides):
    await add_vulnerability(db_session, scan, org, project, **overrides)
    await db_session.commit()


def _url(org_id, scan_id, suffix=""):
    return f"/v1/orgs/{org_id}/scans/{scan_id}/report{suffix}"


# ---------------------------------------------------------------- manifest


@pytest.mark.asyncio
async def test_manifest_pre_generation(client, report_org):
    org, _p, scan, headers = report_org
    r = await client.get(_url(org.id, scan.id), headers=headers)
    assert r.status_code == 200
    body = r.json()
    assert body["scan_id"] == str(scan.id)
    assert body["status"] == "completed"
    assert set(body["available_formats"]) == {"pdf", "sarif", "json", "executive"}
    assert body["pdf"] is None


@pytest.mark.asyncio
async def test_manifest_post_generation(client, report_org, stub_r2):
    org, _p, scan, headers = report_org
    assert (await client.get(_url(org.id, scan.id, "/pdf"), headers=headers)).status_code == 200
    r = await client.get(_url(org.id, scan.id), headers=headers)
    assert r.json()["pdf"]["generated"] is True
    assert r.json()["pdf"]["size_bytes"] > 0


# ---------------------------------------------------------------- pdf


@pytest.mark.asyncio
async def test_pdf_returns_presigned_url(client, report_org, stub_r2):
    org, _p, scan, headers = report_org
    r = await client.get(_url(org.id, scan.id, "/pdf"), headers=headers)
    assert r.status_code == 200
    body = r.json()
    assert body["format"] == "pdf"
    assert body["download_url"].startswith("https://r2.example.test/")
    assert body["expires_in"] == 3600
    assert body["expires_at"] and body["size_bytes"] > 0
    # presigned generated with the 3600s customer expiry (G2-L8).
    assert stub_r2["presigns"][0][1] == 3600
    assert len(stub_r2["puts"]) == 1


@pytest.mark.asyncio
async def test_pdf_route_idempotent(client, report_org, stub_r2):
    org, _p, scan, headers = report_org
    await client.get(_url(org.id, scan.id, "/pdf"), headers=headers)
    await client.get(_url(org.id, scan.id, "/pdf"), headers=headers)
    # Service reuse holds through the endpoint: one upload, same r2_key twice.
    assert len(stub_r2["puts"]) == 1
    assert stub_r2["presigns"][0][0] == stub_r2["presigns"][1][0]


# ---------------------------------------------------------------- sarif / json / executive


@pytest.mark.asyncio
async def test_sarif_inline_conformant(client, db_session, report_org):
    org, project, scan, headers = report_org
    await use_org(db_session, org.id)
    await _seed_vuln(
        db_session, org, project, scan,
        title="SQLi", severity=Severity.CRITICAL, severity_score=9.4, cwe_id="CWE-89",
    )
    r = await client.get(_url(org.id, scan.id, "/sarif"), headers=headers)
    assert r.status_code == 200
    doc = r.json()
    assert doc["version"] == "2.1.0"
    jsonschema.validate(instance=doc, schema=_sarif_schema())
    assert len(doc["runs"][0]["results"]) == 1


@pytest.mark.asyncio
async def test_json_inline_envelope(client, db_session, report_org):
    org, project, scan, headers = report_org
    await use_org(db_session, org.id)
    await _seed_vuln(
        db_session, org, project, scan,
        title="SQLi", severity_score=9.4, ai_fix_text="Use parameterized queries.",
    )
    r = await client.get(_url(org.id, scan.id, "/json"), headers=headers)
    assert r.status_code == 200
    body = r.json()
    assert body["schema_version"] == "1.0"
    assert body["vulnerability_count"] == 1
    assert body["vulnerabilities"][0]["ai_fix_text"] == "Use parameterized queries."


@pytest.mark.asyncio
async def test_executive_returns_summary(client, report_org):
    org, _p, scan, headers = report_org
    r = await client.get(_url(org.id, scan.id, "/executive"), headers=headers)
    assert r.status_code == 200
    body = r.json()
    assert body["scan_id"] == str(scan.id)
    assert body["executive_summary"] == _EXEC_SUMMARY


# ---------------------------------------------------------------- 409 non-terminal


@pytest.mark.asyncio
async def test_409_non_terminal_scan(client, db_session, report_org):
    org, project, _scan, headers = report_org
    await use_org(db_session, org.id)
    queued = Scan(
        organization_id=org.id,
        project_id=project.id,
        scan_type=ScanType.FULL_WEB,
        status=ScanStatus.RUNNING,
        priority="normal",
        config={},
    )
    db_session.add(queued)
    await db_session.commit()
    for suffix in ("", "/pdf", "/sarif", "/json", "/executive"):
        r = await client.get(_url(org.id, queued.id, suffix), headers=headers)
        assert r.status_code == 409, suffix


# ---------------------------------------------------------------- cross-tenant 404


@pytest.mark.asyncio
async def test_cross_tenant_404(client, db_session, report_org, other_org_headers):
    org, _p, scan, _headers = report_org
    for suffix in ("", "/pdf", "/sarif", "/json", "/executive"):
        r = await client.get(_url(org.id, scan.id, suffix), headers=other_org_headers)
        assert r.status_code == 404, suffix


# ---------------------------------------------------------------- empty vulns


@pytest.mark.asyncio
async def test_empty_vulns_all_formats_succeed(client, report_org, stub_r2):
    org, _p, scan, headers = report_org
    for suffix in ("", "/pdf", "/sarif", "/json", "/executive"):
        r = await client.get(_url(org.id, scan.id, suffix), headers=headers)
        assert r.status_code == 200, suffix
