"""Endpoint tests for POST /v1/orgs/{org_id}/scans/compare (Task 4.6).

Nine tests pinning the route contract:

  Happy path + summary (2):
   1. categorized diff in response (plan-literal asserts pass)
   2. summary block carries counts + truncated flag

  Tenant + existence (3):
   3. baseline scan not found → 404
   4. current scan not found → 404
   5. cross-tenant scan_id → 404 (existence-hiding)

  Cross-project + state guards (3):
   6. cross-project comparison → 409 scans_project_mismatch
   7. non-terminal scan (RUNNING) → 409 scan_not_terminal
   8. CANCELED scan → 409 scan_not_terminal (explicit pin)

  Audit (1):
   9. SCAN_COMPARED audit emitted with full details shape
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import select

from app.models.audit import AuditLog
from app.models.identity import Membership, MembershipRole, Organization, User
from app.models.projects import Project
from app.models.raw_findings import EngineCategory, Severity
from app.models.scans import Scan, ScanStatus, ScanType
from app.models.vulnerabilities import Vulnerability, VulnerabilityStatus
from app.services.auth import create_access_token, hash_password
from tests.conftest import use_org


# ---------------------------------------------------------------- helpers


def _vuln(*, scan_id, project_id, org_id, fingerprint, **kw):
    defaults = dict(
        title="x",
        severity=Severity.MEDIUM,
        finding_type="xss",
        engine_category=EngineCategory.DAST,
    )
    defaults.update(kw)
    return Vulnerability(
        scan_id=scan_id,
        project_id=project_id,
        organization_id=org_id,
        fingerprint=fingerprint,
        **defaults,
    )


@pytest_asyncio.fixture
async def cmp_setup(client, db_session):
    """Org + admin + project + 2 completed scans + JWT headers.
    Caller seeds vulnerabilities."""
    org = Organization(name="CR Org", slug=f"cr-{uuid4().hex[:8]}")
    db_session.add(org)
    await db_session.flush()
    await use_org(db_session, org.id)

    user = User(
        email=f"cr-{uuid4().hex[:6]}@t.co",
        hashed_password=hash_password("CrPass-1"),
        full_name="CR",
        email_verified=True,
    )
    db_session.add(user)
    await db_session.flush()
    db_session.add(Membership(user_id=user.id, organization_id=org.id, role=MembershipRole.ADMIN))

    project = Project(
        organization_id=org.id,
        name="CrApp",
        target_url="https://cr.example.com",
        root_domain="example.com",
        domain_verified=True,
    )
    db_session.add(project)
    await db_session.flush()

    t0 = datetime(2026, 11, 1, tzinfo=timezone.utc)
    baseline = Scan(
        organization_id=org.id,
        project_id=project.id,
        scan_type=ScanType.QUICK,
        status=ScanStatus.COMPLETED,
        priority="normal",
        config={},
        created_at=t0,
    )
    current = Scan(
        organization_id=org.id,
        project_id=project.id,
        scan_type=ScanType.QUICK,
        status=ScanStatus.COMPLETED,
        priority="normal",
        config={},
        created_at=t0 + timedelta(days=1),
    )
    db_session.add_all([baseline, current])
    await db_session.commit()
    await db_session.refresh(baseline)
    await db_session.refresh(current)

    return {
        "org": org,
        "user": user,
        "project": project,
        "baseline": baseline,
        "current": current,
        "headers": {"Authorization": f"Bearer {create_access_token(sub=str(user.id))}"},
    }


@pytest_asyncio.fixture
async def other_org_scan(db_session):
    """Second org with its own completed scan — used for cross-tenant test."""
    org = Organization(name="OC Org", slug=f"oc-{uuid4().hex[:8]}")
    db_session.add(org)
    await db_session.flush()
    await use_org(db_session, org.id)
    user = User(
        email=f"oc-{uuid4().hex[:6]}@t.co",
        hashed_password=hash_password("OcPass-1"),
        full_name="Oc",
        email_verified=True,
    )
    db_session.add(user)
    await db_session.flush()
    db_session.add(Membership(user_id=user.id, organization_id=org.id, role=MembershipRole.ADMIN))
    project = Project(
        organization_id=org.id,
        name="OcApp",
        target_url="https://oc.example.com",
        root_domain="example.com",
        domain_verified=True,
    )
    db_session.add(project)
    await db_session.flush()
    scan = Scan(
        organization_id=org.id,
        project_id=project.id,
        scan_type=ScanType.QUICK,
        status=ScanStatus.COMPLETED,
        priority="normal",
        config={},
    )
    db_session.add(scan)
    await db_session.commit()
    await db_session.refresh(scan)
    return {"org": org, "scan": scan}


def _url(s):
    return f"/v1/orgs/{s['org'].id}/scans/compare"


# ============================================================ 1. happy path


@pytest.mark.asyncio
async def test_compare_returns_identity_link_diff(cmp_setup, client, db_session):
    s = cmp_setup
    b, c = s["baseline"], s["current"]
    b1 = _vuln(
        scan_id=b.id,
        project_id=s["project"].id,
        org_id=s["org"].id,
        fingerprint="f1",
        title="persist",
    )
    db_session.add(b1)
    await db_session.flush()
    c1 = _vuln(
        scan_id=c.id,
        project_id=s["project"].id,
        org_id=s["org"].id,
        fingerprint="f1",
        title="persist",
        previous_id=b1.id,
    )
    db_session.add(c1)
    await db_session.flush()
    b1.superseded_by_id = c1.id
    db_session.add_all(
        [
            _vuln(
                scan_id=b.id,
                project_id=s["project"].id,
                org_id=s["org"].id,
                fingerprint="f2",
                title="fixed",
                status=VulnerabilityStatus.RESOLVED,
            ),
            _vuln(
                scan_id=b.id,
                project_id=s["project"].id,
                org_id=s["org"].id,
                fingerprint="f3",
                title="uncovered",
            ),
            _vuln(
                scan_id=c.id,
                project_id=s["project"].id,
                org_id=s["org"].id,
                fingerprint="f4",
                title="new",
            ),
            _vuln(
                scan_id=c.id,
                project_id=s["project"].id,
                org_id=s["org"].id,
                fingerprint="f5",
                title="back",
                regression=True,
            ),
        ]
    )
    await db_session.commit()

    r = await client.post(
        f"/v1/orgs/{s['org'].id}/scans/compare",
        json={"baseline_scan_id": str(b.id), "current_scan_id": str(c.id)},
        headers=s["headers"],
    )
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["baseline"]["id"] == str(b.id) and data["current"]["id"] == str(c.id)
    assert [v["title"] for v in data["persisting"]] == ["persist"]
    assert [v["title"] for v in data["fixed"]] == ["fixed"]
    assert [v["title"] for v in data["not_covered"]] == ["uncovered"]
    assert [v["title"] for v in data["new"]] == ["new"]
    assert [v["title"] for v in data["regressions"]] == ["back"]
    assert data["summary"] == {
        "new": 1,
        "regressions": 1,
        "persisting": 1,
        "fixed": 1,
        "not_covered": 1,
        "triaged": 0,
        "truncated": False,
        "scope_covered": True,
    }


@pytest.mark.asyncio
async def test_compare_defaults_to_previous_same_type_scan(cmp_setup, client):
    s = cmp_setup
    r = await client.post(
        f"/v1/orgs/{s['org'].id}/scans/compare",
        json={"current_scan_id": str(s["current"].id)},
        headers=s["headers"],
    )
    assert r.status_code == 200, r.text
    assert r.json()["baseline"]["id"] == str(s["baseline"].id)
    # The oldest scan has nothing before it.
    r = await client.post(
        f"/v1/orgs/{s['org'].id}/scans/compare",
        json={"current_scan_id": str(s["baseline"].id)},
        headers=s["headers"],
    )
    assert r.status_code == 404 and r.json()["detail"] == "no_baseline"
    # Reversed order is refused.
    r = await client.post(
        f"/v1/orgs/{s['org'].id}/scans/compare",
        json={"baseline_scan_id": str(s["current"].id), "current_scan_id": str(s["baseline"].id)},
        headers=s["headers"],
    )
    assert r.status_code == 409 and r.json()["detail"] == "baseline_not_older"


@pytest.mark.asyncio
async def test_compare_baseline_scan_not_found_returns_404(cmp_setup, client):
    s = cmp_setup
    r = await client.post(
        _url(s),
        json={
            "baseline_scan_id": str(uuid4()),
            "current_scan_id": str(s["current"].id),
        },
        headers=s["headers"],
    )
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_compare_current_scan_not_found_returns_404(cmp_setup, client):
    s = cmp_setup
    r = await client.post(
        _url(s),
        json={
            "baseline_scan_id": str(s["baseline"].id),
            "current_scan_id": str(uuid4()),
        },
        headers=s["headers"],
    )
    assert r.status_code == 404


# ============================================================ 5. cross-tenant


@pytest.mark.asyncio
async def test_compare_cross_tenant_scan_returns_404(cmp_setup, other_org_scan, client):
    """Existence-hiding pin: a scan_id from another tenant returns 404
    before any vulnerability data is exposed. Same discipline as
    Task 4.5 cancel cross-tenant."""
    s = cmp_setup
    other = other_org_scan
    r = await client.post(
        _url(s),
        json={
            "baseline_scan_id": str(s["baseline"].id),
            "current_scan_id": str(other["scan"].id),  # other tenant's scan
        },
        headers=s["headers"],
    )
    assert r.status_code == 404


# ============================================================ 6. cross-project 409


@pytest.mark.asyncio
async def test_compare_cross_project_returns_409(cmp_setup, client, db_session):
    """Cross-project comparison rejected with 409 scans_project_mismatch.
    Both scans org-scoped (visible) but project_ids differ — semantic
    conflict."""
    s = cmp_setup
    # Build a second project + scan in the same org.
    p2 = Project(
        organization_id=s["org"].id,
        name="OtherProj",
        target_url="https://op.example.com",
        root_domain="example.com",
        domain_verified=True,
    )
    db_session.add(p2)
    await db_session.flush()
    other_proj_scan = Scan(
        organization_id=s["org"].id,
        project_id=p2.id,
        scan_type=ScanType.QUICK,
        status=ScanStatus.COMPLETED,
        priority="normal",
        config={},
    )
    db_session.add(other_proj_scan)
    await db_session.commit()
    await db_session.refresh(other_proj_scan)

    r = await client.post(
        _url(s),
        json={
            "baseline_scan_id": str(s["baseline"].id),
            "current_scan_id": str(other_proj_scan.id),
        },
        headers=s["headers"],
    )
    assert r.status_code == 409
    assert r.json()["detail"] == "scans_project_mismatch"


# ============================================================ 7. non-terminal 409


@pytest.mark.asyncio
async def test_compare_non_terminal_scan_returns_409(cmp_setup, client, db_session):
    """Comparing against a still-running scan reports fake 'resolved'
    findings — vulnerabilities not yet discovered, not actually
    resolved. 409 to prevent the misleading data."""
    s = cmp_setup
    s["current"].status = ScanStatus.RUNNING
    await db_session.commit()
    r = await client.post(
        _url(s),
        json={
            "baseline_scan_id": str(s["baseline"].id),
            "current_scan_id": str(s["current"].id),
        },
        headers=s["headers"],
    )
    assert r.status_code == 409
    assert r.json()["detail"] == "scan_not_terminal"


# ============================================================ 8. canceled 409


@pytest.mark.asyncio
async def test_compare_canceled_scan_returns_409(cmp_setup, client, db_session):
    """Explicit pin: CANCELED is rejected even though it's a terminal
    state — the scan was aborted by user before completion, so the
    data is incomplete by definition."""
    s = cmp_setup
    s["baseline"].status = ScanStatus.CANCELED
    await db_session.commit()
    r = await client.post(
        _url(s),
        json={
            "baseline_scan_id": str(s["baseline"].id),
            "current_scan_id": str(s["current"].id),
        },
        headers=s["headers"],
    )
    assert r.status_code == 409
    assert r.json()["detail"] == "scan_not_terminal"


# ============================================================ 9. audit emission


@pytest.mark.asyncio
async def test_compare_emits_scan_compared_audit(cmp_setup, client, db_session):
    """Audit detail shape: baseline_scan_id, current_scan_id, counts,
    truncated. Self-explanatory audit row, no joins needed for ops
    review. resource_id is the current_scan_id (newer scan)."""
    s = cmp_setup
    r = await client.post(
        _url(s),
        json={
            "baseline_scan_id": str(s["baseline"].id),
            "current_scan_id": str(s["current"].id),
        },
        headers=s["headers"],
    )
    assert r.status_code == 200

    audits = (
        (await db_session.execute(select(AuditLog).where(AuditLog.action == "scan.compared")))
        .scalars()
        .all()
    )
    assert len(audits) == 1
    a = audits[0]
    assert a.actor_id == s["user"].id
    assert a.organization_id == s["org"].id
    assert a.resource_id == s["current"].id
    assert a.details["baseline_scan_id"] == str(s["baseline"].id)
    assert a.details["current_scan_id"] == str(s["current"].id)
    assert a.details["new_count"] == 0
    assert a.details["fixed_count"] == 0
    assert a.details["persisting_count"] == 0
    assert a.details["not_covered_count"] == 0
    assert a.details["truncated"] is False
