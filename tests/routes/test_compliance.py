"""End-to-end tests for the M10.C compliance endpoints (Task 10.5; SPEC §6).

Covers the 3 org-scoped GETs + three-state posture (pass/fail/not_assessed) +
409 non-terminal + cross-tenant 404. Compliance reference data is seeded via
``seed_compliance_data`` (the runtime helper) because the test harness builds
schema via ``create_all``, not migrations — the C1 seed-split resolution.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
import pytest_asyncio

from app.models.identity import Membership, MembershipRole, Organization, User
from app.models.projects import Project
from app.models.scans import Scan, ScanStatus, ScanType
from app.services.auth import create_access_token, hash_password
from app.services.compliance.frameworks import seed_compliance_data
from tests.conftest import use_org
from tests.services.ai.conftest import add_vulnerability


@pytest_asyncio.fixture
async def compliance_org(client, db_session):
    """Org A admin + project + COMPLETED scan + seeded compliance data:
    (org, project, scan, headers)."""
    org = Organization(name="Comp Org", slug=f"comporg-{uuid4().hex[:8]}")
    db_session.add(org)
    await db_session.flush()
    await use_org(db_session, org.id)
    user = User(
        email=f"comp-{uuid4().hex[:6]}@t.co",
        hashed_password=hash_password("CompPass-1"),
        full_name="Comp Admin",
        email_verified=True,
    )
    db_session.add(user)
    await db_session.flush()
    db_session.add(
        Membership(user_id=user.id, organization_id=org.id, role=MembershipRole.ADMIN)
    )
    project = Project(
        organization_id=org.id,
        name="CompApp",
        target_url="https://comp.example.com",
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
    await seed_compliance_data(db_session)  # global reference data
    await db_session.commit()
    headers = {"Authorization": f"Bearer {create_access_token(sub=str(user.id))}"}
    return org, project, scan, headers


@pytest_asyncio.fixture
async def other_org_headers(db_session):
    org = Organization(name="Other Comp Org", slug=f"othercomp-{uuid4().hex[:8]}")
    db_session.add(org)
    await db_session.flush()
    await use_org(db_session, org.id)
    user = User(
        email=f"othercomp-{uuid4().hex[:6]}@t.co",
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


def _states(body):
    return {c["control_id"]: c["state"] for c in body["controls"]}


# ---------------------------------------------------------------- frameworks


@pytest.mark.asyncio
async def test_list_frameworks(client, compliance_org):
    org, _p, _s, headers = compliance_org
    r = await client.get(f"/v1/orgs/{org.id}/compliance/frameworks", headers=headers)
    assert r.status_code == 200
    by_slug = {f["slug"]: f for f in r.json()["frameworks"]}
    assert set(by_slug) == {"soc2", "iso27001"}
    assert by_slug["iso27001"]["version"] == "2013"
    assert len(by_slug["soc2"]["controls"]) == 6


# ---------------------------------------------------------------- per-scan posture


@pytest.mark.asyncio
async def test_scan_posture_three_states(client, db_session, compliance_org):
    """The acceptance-grade case: a CWE-89 finding drives all three states."""
    org, project, scan, headers = compliance_org
    await use_org(db_session, org.id)
    await add_vulnerability(db_session, scan, org, project, cwe_id="CWE-89")
    await db_session.commit()

    r = await client.get(
        f"/v1/orgs/{org.id}/scans/{scan.id}/compliance/soc2", headers=headers
    )
    assert r.status_code == 200
    states = _states(r.json())
    assert states["CC6.1"] == "fail"          # CWE-89 maps to CC6.1
    assert states["CC6.6"] == "pass"          # mapped (CWE-434) but not hit
    assert states["CC7.2"] == "not_assessed"  # no CWE mapping at all
    summary = r.json()["summary"]
    assert summary["fail"] >= 1 and summary["not_assessed"] >= 1


@pytest.mark.asyncio
async def test_scan_posture_empty_scan(client, compliance_org):
    org, _p, scan, headers = compliance_org
    r = await client.get(
        f"/v1/orgs/{org.id}/scans/{scan.id}/compliance/soc2", headers=headers
    )
    assert r.status_code == 200
    states = _states(r.json())
    assert states["CC6.1"] == "pass"          # mapped, no finding
    assert states["CC7.2"] == "not_assessed"  # unmappable
    assert "fail" not in states.values()


@pytest.mark.asyncio
async def test_scan_posture_unknown_framework_404(client, compliance_org):
    org, _p, scan, headers = compliance_org
    r = await client.get(
        f"/v1/orgs/{org.id}/scans/{scan.id}/compliance/pci", headers=headers
    )
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_scan_posture_non_terminal_409(client, db_session, compliance_org):
    org, project, _scan, headers = compliance_org
    await use_org(db_session, org.id)
    running = Scan(
        organization_id=org.id,
        project_id=project.id,
        scan_type=ScanType.FULL_WEB,
        status=ScanStatus.RUNNING,
        priority="normal",
        config={},
    )
    db_session.add(running)
    await db_session.commit()
    r = await client.get(
        f"/v1/orgs/{org.id}/scans/{running.id}/compliance/soc2", headers=headers
    )
    assert r.status_code == 409


@pytest.mark.asyncio
async def test_scan_posture_cross_tenant_404(client, compliance_org, other_org_headers):
    org, _p, scan, _headers = compliance_org
    r = await client.get(
        f"/v1/orgs/{org.id}/scans/{scan.id}/compliance/soc2", headers=other_org_headers
    )
    assert r.status_code == 404


# ---------------------------------------------------------------- org posture


@pytest.mark.asyncio
async def test_org_posture_aggregate(client, db_session, compliance_org):
    org, project, scan, headers = compliance_org
    await use_org(db_session, org.id)
    await add_vulnerability(db_session, scan, org, project, cwe_id="CWE-89")
    await db_session.commit()

    r = await client.get(f"/v1/orgs/{org.id}/compliance/posture", headers=headers)
    assert r.status_code == 200
    by_slug = {f["slug"]: f for f in r.json()["frameworks"]}
    soc2_states = {c["control_id"]: c["state"] for c in by_slug["soc2"]["controls"]}
    assert soc2_states["CC6.1"] == "fail"          # any org scan hits it → org fail
    assert soc2_states["CC7.2"] == "not_assessed"


@pytest.mark.asyncio
async def test_org_posture_ignores_non_open_vulnerabilities(
    client, db_session, compliance_org
):
    """M11: resolved / false-positive / accepted-risk rows no longer fail a
    control; only open work counts."""
    from app.models.vulnerabilities import VulnerabilityStatus

    org, project, scan, headers = compliance_org
    await use_org(db_session, org.id)
    vuln = await add_vulnerability(db_session, scan, org, project, cwe_id="CWE-89")
    vuln.status = VulnerabilityStatus.RESOLVED
    await db_session.commit()

    r = await client.get(f"/v1/orgs/{org.id}/compliance/posture", headers=headers)
    assert r.status_code == 200
    by_slug = {f["slug"]: f for f in r.json()["frameworks"]}
    soc2_states = {c["control_id"]: c["state"] for c in by_slug["soc2"]["controls"]}
    assert soc2_states["CC6.1"] == "pass"

    vuln.status = VulnerabilityStatus.OPEN
    await db_session.commit()
    r = await client.get(f"/v1/orgs/{org.id}/compliance/posture", headers=headers)
    soc2_states = {c["control_id"]: c["state"] for c in
                   {f["slug"]: f for f in r.json()["frameworks"]}["soc2"]["controls"]}
    assert soc2_states["CC6.1"] == "fail"


@pytest.mark.asyncio
async def test_org_posture_cross_tenant_isolated(
    client, db_session, compliance_org, other_org_headers
):
    """Org B's posture must not see org A's failing finding."""
    org, project, scan, _headers = compliance_org
    await use_org(db_session, org.id)
    await add_vulnerability(db_session, scan, org, project, cwe_id="CWE-89")
    await db_session.commit()

    # Org B has no vulns — CC6.1 should be pass (mapped, unhit) for them.
    r = await client.get(
        f"/v1/orgs/{org.id}/compliance/posture", headers=other_org_headers
    )
    # Org B is not a member of org A's org_id path → 404 (ADR-012 collapse).
    assert r.status_code == 404
