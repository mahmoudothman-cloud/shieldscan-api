"""Tests for the scan read endpoints (M11 pre-work).

    GET /v1/orgs/{org_id}/scans
    GET /v1/orgs/{org_id}/projects/{project_id}/scans
    GET /v1/orgs/{org_id}/scans/{scan_id}

Scenarios:
  1. unauthenticated → 401 on all three
  2. cross-tenant org_id → 404 (membership gate)
  3. org list: newest first, pagination meta, per-scan job + vuln rollups
  4. org list: status CSV filter, scan_type filter, project_id filter
  5. org list: invalid status token → 422; invalid sort key → 422
  6. project list: scoped to the project; missing / cross-tenant project → 404
  7. detail: header fields, jobs ordered by engine, raw + severity counts,
     executive_summary_available
  8. detail: nonexistent / cross-tenant scan → 404

HTTP-level only — pure reads, no Redis involvement.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
import pytest_asyncio

from app.models.identity import Membership, MembershipRole, Organization, User
from app.models.projects import Project
from app.models.raw_findings import EngineCategory, RawFinding, Severity
from app.models.scans import Scan, ScanJob, ScanStatus, ScanType
from app.models.vulnerabilities import Vulnerability
from app.services.auth import create_access_token, hash_password
from tests.conftest import use_org


# ---------------------------------------------------------------- helpers


async def _mk_org(db_session, tag: str):
    org = Organization(name=f"{tag} Org", slug=f"{tag}-{uuid4().hex[:8]}")
    db_session.add(org)
    await db_session.flush()
    await use_org(db_session, org.id)
    user = User(
        email=f"{tag}-{uuid4().hex[:6]}@t.co",
        hashed_password=hash_password("ReadPass-1"),
        full_name=tag,
        email_verified=True,
    )
    db_session.add(user)
    await db_session.flush()
    db_session.add(
        Membership(user_id=user.id, organization_id=org.id, role=MembershipRole.ADMIN)
    )
    return org, user


async def _mk_project(db_session, org, name: str, url: str):
    project = Project(
        organization_id=org.id,
        name=name,
        target_url=url,
        root_domain="example.com",
        domain_verified=True,
    )
    db_session.add(project)
    await db_session.flush()
    return project


async def _mk_scan(
    db_session,
    org,
    project,
    *,
    scan_type=ScanType.FULL_WEB,
    status=ScanStatus.COMPLETED,
    created_at=None,
    executive_summary=None,
):
    scan = Scan(
        organization_id=org.id,
        project_id=project.id,
        scan_type=scan_type,
        status=status,
        priority="normal",
        config={},
        executive_summary=executive_summary,
    )
    if created_at is not None:
        scan.created_at = created_at
    db_session.add(scan)
    await db_session.flush()
    return scan


async def _mk_job(db_session, org, scan, engine: str, status: str, findings: int = 0):
    db_session.add(
        ScanJob(
            organization_id=org.id,
            scan_id=scan.id,
            engine=engine,
            target_url="https://shop.example.com",
            status=status,
            idempotency_key=f"{scan.id}:{engine}:{uuid4().hex[:6]}",
            finding_count=findings,
            duration_ms=1200 if status != "queued" else None,
            error_message="nikto timed out after 15m0s" if status == "failed" else None,
        )
    )


async def _mk_vuln(db_session, org, scan, project, severity: Severity):
    db_session.add(
        Vulnerability(
            organization_id=org.id,
            scan_id=scan.id,
            project_id=project.id,
            title=f"{severity.value} finding",
            severity=severity,
            finding_type="xss",
            engine_category=EngineCategory.DAST,
            target_url="https://shop.example.com/x",
            fingerprint=uuid4().hex,
        )
    )


async def _mk_raw(db_session, org, scan, n: int):
    for i in range(n):
        db_session.add(
            RawFinding(
                organization_id=org.id,
                scan_id=scan.id,
                tool_name="nuclei",
                engine_category=EngineCategory.DAST,
                finding_type="xss",
                severity=Severity.LOW,
                title=f"raw {i}",
                target_url="https://shop.example.com/x",
                fingerprint=uuid4().hex,
            )
        )


# ---------------------------------------------------------------- fixtures


@pytest_asyncio.fixture
async def reads_setup(client, db_session):
    """One org, two projects, three scans with jobs/vulns/raw findings."""
    org, user = await _mk_org(db_session, "rd")
    p1 = await _mk_project(db_session, org, "Shop", "https://shop.example.com")
    p2 = await _mk_project(db_session, org, "Blog", "https://blog.example.com")

    t0 = datetime(2026, 11, 1, 12, 0, tzinfo=timezone.utc)
    s_old = await _mk_scan(
        db_session, org, p1, status=ScanStatus.PARTIAL, created_at=t0
    )
    s_mid = await _mk_scan(
        db_session, org, p2, scan_type=ScanType.QUICK,
        status=ScanStatus.COMPLETED, created_at=t0 + timedelta(days=1),
    )
    s_new = await _mk_scan(
        db_session, org, p1, status=ScanStatus.RUNNING,
        created_at=t0 + timedelta(days=2), executive_summary="Two criticals.",
    )

    # s_old: 7 jobs, 6 done + 1 failed (the "6 of 7" case), 3 vulns.
    for eng in ("recon", "nmap", "sslyze", "wapiti", "zap", "nuclei"):
        await _mk_job(db_session, org, s_old, eng, "completed", findings=5)
    await _mk_job(db_session, org, s_old, "nikto", "failed")
    await _mk_vuln(db_session, org, s_old, p1, Severity.CRITICAL)
    await _mk_vuln(db_session, org, s_old, p1, Severity.HIGH)
    await _mk_vuln(db_session, org, s_old, p1, Severity.HIGH)
    await _mk_raw(db_session, org, s_old, 4)

    # s_new: 3 jobs, 1 done, 2 queued, no vulns yet.
    await _mk_job(db_session, org, s_new, "recon", "completed")
    await _mk_job(db_session, org, s_new, "nuclei", "queued")
    await _mk_job(db_session, org, s_new, "zap", "queued")

    await db_session.commit()
    for s in (s_old, s_mid, s_new):
        await db_session.refresh(s)

    return {
        "org": org,
        "p1": p1,
        "p2": p2,
        "old": s_old,
        "mid": s_mid,
        "new": s_new,
        "headers": {"Authorization": f"Bearer {create_access_token(sub=str(user.id))}"},
    }


@pytest_asyncio.fixture
async def other_org(db_session):
    org, user = await _mk_org(db_session, "ox")
    project = await _mk_project(db_session, org, "Other", "https://other.example.com")
    scan = await _mk_scan(db_session, org, project)
    await db_session.commit()
    await db_session.refresh(scan)
    return {
        "org": org,
        "project": project,
        "scan": scan,
        "headers": {"Authorization": f"Bearer {create_access_token(sub=str(user.id))}"},
    }


def _org_list(org_id):
    return f"/v1/orgs/{org_id}/scans"


def _proj_list(org_id, project_id):
    return f"/v1/orgs/{org_id}/projects/{project_id}/scans"


def _detail(org_id, scan_id):
    return f"/v1/orgs/{org_id}/scans/{scan_id}"


# ============================================================ 1-2. auth paths


@pytest.mark.asyncio
async def test_reads_require_auth(client, reads_setup):
    org = reads_setup["org"]
    assert (await client.get(_org_list(org.id))).status_code == 401
    assert (await client.get(_proj_list(org.id, reads_setup["p1"].id))).status_code == 401
    assert (await client.get(_detail(org.id, reads_setup["old"].id))).status_code == 401


@pytest.mark.asyncio
async def test_reads_cross_tenant_org_is_404(client, reads_setup, other_org):
    """A member of org B asking for org A's scans gets 404, not a list."""
    org = reads_setup["org"]
    h = other_org["headers"]
    assert (await client.get(_org_list(org.id), headers=h)).status_code == 404
    assert (
        await client.get(_proj_list(org.id, reads_setup["p1"].id), headers=h)
    ).status_code == 404
    assert (
        await client.get(_detail(org.id, reads_setup["old"].id), headers=h)
    ).status_code == 404


# ============================================================ 3-5. org list


@pytest.mark.asyncio
async def test_org_list_newest_first_with_rollups(client, reads_setup):
    r = await client.get(_org_list(reads_setup["org"].id), headers=reads_setup["headers"])
    assert r.status_code == 200
    body = r.json()
    ids = [i["id"] for i in body["items"]]
    assert ids == [
        str(reads_setup["new"].id),
        str(reads_setup["mid"].id),
        str(reads_setup["old"].id),
    ]
    assert body["pagination"] == {
        "page": 1, "per_page": 20, "total": 3, "total_pages": 1,
        "has_next": False, "has_prev": False,
    }
    by_id = {i["id"]: i for i in body["items"]}
    old = by_id[str(reads_setup["old"].id)]
    assert old["project_name"] == "Shop"
    assert old["status"] == "partial"
    assert (old["jobs_total"], old["jobs_terminal"]) == (7, 7)
    assert old["vulnerability_count"] == 3
    new = by_id[str(reads_setup["new"].id)]
    assert (new["jobs_total"], new["jobs_terminal"]) == (3, 1)
    assert new["vulnerability_count"] == 0
    mid = by_id[str(reads_setup["mid"].id)]
    assert (mid["jobs_total"], mid["jobs_terminal"], mid["vulnerability_count"]) == (0, 0, 0)
    assert mid["scan_type"] == "quick"


@pytest.mark.asyncio
async def test_org_list_pagination(client, reads_setup):
    h = reads_setup["headers"]
    r = await client.get(
        _org_list(reads_setup["org"].id), params={"per_page": 2, "page": 2}, headers=h
    )
    body = r.json()
    assert [i["id"] for i in body["items"]] == [str(reads_setup["old"].id)]
    assert body["pagination"]["total_pages"] == 2
    assert body["pagination"]["has_prev"] is True
    assert body["pagination"]["has_next"] is False


@pytest.mark.asyncio
async def test_org_list_filters(client, reads_setup):
    h = reads_setup["headers"]
    org_id = reads_setup["org"].id

    r = await client.get(_org_list(org_id), params={"status": "running,partial"}, headers=h)
    assert {i["status"] for i in r.json()["items"]} == {"running", "partial"}

    r = await client.get(_org_list(org_id), params={"scan_type": "quick"}, headers=h)
    assert [i["id"] for i in r.json()["items"]] == [str(reads_setup["mid"].id)]

    r = await client.get(
        _org_list(org_id), params={"project_id": str(reads_setup["p1"].id)}, headers=h
    )
    assert {i["project_id"] for i in r.json()["items"]} == {str(reads_setup["p1"].id)}
    assert r.json()["pagination"]["total"] == 2

    r = await client.get(_org_list(org_id), params={"sort": "created_at"}, headers=h)
    assert r.json()["items"][0]["id"] == str(reads_setup["old"].id)


@pytest.mark.asyncio
async def test_org_list_rejects_bad_params(client, reads_setup):
    h = reads_setup["headers"]
    org_id = reads_setup["org"].id
    assert (
        await client.get(_org_list(org_id), params={"status": "exploded"}, headers=h)
    ).status_code == 422
    assert (
        await client.get(_org_list(org_id), params={"sort": "-priority"}, headers=h)
    ).status_code == 422
    assert (
        await client.get(_org_list(org_id), params={"per_page": 101}, headers=h)
    ).status_code == 422


# ============================================================ 6. project list


@pytest.mark.asyncio
async def test_project_list_is_scoped(client, reads_setup):
    h = reads_setup["headers"]
    org_id = reads_setup["org"].id
    r = await client.get(_proj_list(org_id, reads_setup["p1"].id), headers=h)
    assert r.status_code == 200
    assert [i["id"] for i in r.json()["items"]] == [
        str(reads_setup["new"].id),
        str(reads_setup["old"].id),
    ]
    r = await client.get(_proj_list(org_id, reads_setup["p2"].id), headers=h)
    assert [i["id"] for i in r.json()["items"]] == [str(reads_setup["mid"].id)]


@pytest.mark.asyncio
async def test_project_list_missing_or_foreign_project_is_404(
    client, reads_setup, other_org
):
    h = reads_setup["headers"]
    org_id = reads_setup["org"].id
    assert (await client.get(_proj_list(org_id, uuid4()), headers=h)).status_code == 404
    # Project exists, but in another tenant → still 404, never an empty 200.
    assert (
        await client.get(_proj_list(org_id, other_org["project"].id), headers=h)
    ).status_code == 404


# ============================================================ 7-8. detail


@pytest.mark.asyncio
async def test_detail_shape(client, reads_setup):
    h = reads_setup["headers"]
    old = reads_setup["old"]
    r = await client.get(_detail(reads_setup["org"].id, old.id), headers=h)
    assert r.status_code == 200
    body = r.json()
    assert body["id"] == str(old.id)
    assert body["project_name"] == "Shop"
    assert body["target_url"] == "https://shop.example.com"
    assert body["status"] == "partial"
    assert body["scan_type"] == "full_web"
    assert body["executive_summary_available"] is False
    assert body["raw_finding_count"] == 4
    assert body["vulnerability_count"] == 3
    assert body["severity_counts"] == {
        "critical": 1, "high": 2, "medium": 0, "low": 0, "info": 0
    }
    engines = [j["engine"] for j in body["jobs"]]
    assert engines == sorted(engines)
    assert len(engines) == 7
    nikto = next(j for j in body["jobs"] if j["engine"] == "nikto")
    assert nikto["status"] == "failed"
    assert nikto["error_message"] == "nikto timed out after 15m0s"
    assert nikto["finding_count"] == 0
    nmap = next(j for j in body["jobs"] if j["engine"] == "nmap")
    assert nmap["finding_count"] == 5 and nmap["duration_ms"] == 1200


@pytest.mark.asyncio
async def test_detail_executive_summary_flag(client, reads_setup):
    h = reads_setup["headers"]
    r = await client.get(_detail(reads_setup["org"].id, reads_setup["new"].id), headers=h)
    assert r.json()["executive_summary_available"] is True
    assert r.json()["severity_counts"]["critical"] == 0


@pytest.mark.asyncio
async def test_detail_missing_or_foreign_scan_is_404(client, reads_setup, other_org):
    h = reads_setup["headers"]
    org_id = reads_setup["org"].id
    assert (await client.get(_detail(org_id, uuid4()), headers=h)).status_code == 404
    assert (
        await client.get(_detail(org_id, other_org["scan"].id), headers=h)
    ).status_code == 404
