"""Tests for the attack-surface endpoint (Task 8.3β).

GET /v1/orgs/{org_id}/scans/{scan_id}/attack-surface — SPEC §6.3.

8 scenarios:
  1. unauthenticated → 401
  2. cross-tenant scan_id → 404 (existence-hiding)
  3. nonexistent scan → 404
  4. populated surface → 200 with aggregate counts + per-subdomain rows
  5. empty surface (no recon rows) → 200 empty payload (Y4)
  6. timeout-status bucketing → live/dead aggregate (Y1); row-level
     status preserved
  7. vulnerability_count is 0 pre-M9 even with populated surface (Y2)
  8. vulnerability_count reflects vulnerabilities-table rows when present
     (Y2 structural correctness for post-M9)

HTTP-level only — the endpoint is a pure read aggregation, fully
exercisable via the FastAPI client (no SSE streaming caveat).
"""

from __future__ import annotations

from uuid import uuid4

import pytest
import pytest_asyncio

from app.models.identity import (
    Membership,
    MembershipRole,
    Organization,
    User,
)
from app.models.projects import Project
from app.models.raw_findings import EngineCategory, Severity
from app.models.recon import AttackSurface, SubdomainStatus
from app.models.scans import Scan, ScanStatus, ScanType
from app.models.vulnerabilities import Vulnerability
from app.services.auth import create_access_token, hash_password
from tests.conftest import use_org


# ---------------------------------------------------------------- helpers


async def _seed_attack_surface(
    db_session,
    scan,
    org,
    *,
    full_url,
    status=SubdomainStatus.LIVE,
    status_code=200,
    tech_stack=None,
    root_domain="example.com",
):
    """Insert one AttackSurface row (recon-discovered) for a scan."""
    db_session.add(
        AttackSurface(
            organization_id=org.id,
            scan_id=scan.id,
            root_domain=root_domain,
            subdomain=full_url.split("://", 1)[-1],
            full_url=full_url,
            status=status,
            status_code=status_code,
            tech_stack=tech_stack,
        )
    )
    await db_session.commit()


async def _seed_vulnerability(db_session, scan, org, project, *, target_url):
    """Insert one Vulnerability row bound to a target_url (post-M9 shape)."""
    db_session.add(
        Vulnerability(
            organization_id=org.id,
            scan_id=scan.id,
            project_id=project.id,
            title="Reflected XSS",
            severity=Severity.HIGH,
            finding_type="xss",
            engine_category=EngineCategory.DAST,
            target_url=target_url,
            fingerprint=uuid4().hex,
        )
    )
    await db_session.commit()


# ---------------------------------------------------------------- fixtures


@pytest_asyncio.fixture
async def surface_setup(client, db_session):
    """Org + admin + web project + scan + JWT headers (no surface seeded)."""
    org = Organization(name="AS Org", slug=f"as-{uuid4().hex[:8]}")
    db_session.add(org)
    await db_session.flush()
    await use_org(db_session, org.id)

    user = User(
        email=f"as-{uuid4().hex[:6]}@t.co",
        hashed_password=hash_password("AsPass-1"),
        full_name="AS",
        email_verified=True,
    )
    db_session.add(user)
    await db_session.flush()
    db_session.add(
        Membership(
            user_id=user.id,
            organization_id=org.id,
            role=MembershipRole.ADMIN,
        )
    )

    project = Project(
        organization_id=org.id,
        name="ASApp",
        target_url="https://shop.example.com",
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
    await db_session.commit()
    await db_session.refresh(scan)

    return {
        "org": org,
        "user": user,
        "project": project,
        "scan": scan,
        "headers": {
            "Authorization": f"Bearer {create_access_token(sub=str(user.id))}"
        },
    }


@pytest_asyncio.fixture
async def other_org_scan(db_session):
    """Second org with its own scan — for the cross-tenant test."""
    org = Organization(name="Other AS Org", slug=f"oas-{uuid4().hex[:8]}")
    db_session.add(org)
    await db_session.flush()
    await use_org(db_session, org.id)
    user = User(
        email=f"oas-{uuid4().hex[:6]}@t.co",
        hashed_password=hash_password("OasPass-1"),
        full_name="Oas",
        email_verified=True,
    )
    db_session.add(user)
    await db_session.flush()
    db_session.add(
        Membership(
            user_id=user.id, organization_id=org.id, role=MembershipRole.ADMIN
        )
    )
    project = Project(
        organization_id=org.id,
        name="OasApp",
        target_url="https://oas.example.com",
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
    await db_session.commit()
    await db_session.refresh(scan)
    return {"org": org, "scan": scan}


def _url(org_id, scan_id):
    return f"/v1/orgs/{org_id}/scans/{scan_id}/attack-surface"


# ============================================================ 1-3. auth / 404 paths


@pytest.mark.asyncio
async def test_get_attack_surface_unauthenticated_returns_401(
    surface_setup, client
):
    s = surface_setup
    r = await client.get(_url(s["org"].id, s["scan"].id))
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_get_attack_surface_cross_tenant_returns_404(
    surface_setup, other_org_scan, client
):
    """Existence-hiding: a scan_id from another org → 404, not 403."""
    s = surface_setup
    other = other_org_scan
    r = await client.get(
        _url(s["org"].id, other["scan"].id), headers=s["headers"]
    )
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_get_attack_surface_nonexistent_returns_404(surface_setup, client):
    s = surface_setup
    r = await client.get(_url(s["org"].id, uuid4()), headers=s["headers"])
    assert r.status_code == 404


# ============================================================ 4. populated surface


@pytest.mark.asyncio
async def test_get_attack_surface_with_populated_surface_returns_200(
    surface_setup, db_session, client
):
    s = surface_setup
    await _seed_attack_surface(
        db_session,
        s["scan"],
        s["org"],
        full_url="https://api.example.com",
        status=SubdomainStatus.LIVE,
        status_code=200,
        tech_stack=["nginx", "Node.js"],
    )
    await _seed_attack_surface(
        db_session,
        s["scan"],
        s["org"],
        full_url="https://www.example.com",
        status=SubdomainStatus.LIVE,
        status_code=200,
    )
    await _seed_attack_surface(
        db_session,
        s["scan"],
        s["org"],
        full_url="https://old.example.com",
        status=SubdomainStatus.DEAD,
        status_code=None,
    )

    r = await client.get(_url(s["org"].id, s["scan"].id), headers=s["headers"])
    assert r.status_code == 200
    body = r.json()
    assert body["root_domain"] == "example.com"
    assert body["total_discovered"] == 3
    assert body["live"] == 2
    assert body["dead"] == 1
    assert len(body["subdomains"]) == 3

    by_url = {entry["url"]: entry for entry in body["subdomains"]}
    api = by_url["https://api.example.com"]
    assert api["status"] == "live"
    assert api["status_code"] == 200
    assert api["tech_stack"] == ["nginx", "Node.js"]
    assert api["vulnerability_count"] == 0  # no vulnerabilities seeded


# ============================================================ 5. empty surface (Y4)


@pytest.mark.asyncio
async def test_get_attack_surface_empty_surface_returns_200_with_empty_payload(
    surface_setup, client
):
    """Y4: scan exists, no AttackSurface rows → 200 empty payload (not
    404). root_domain falls back to the bound project's target_url."""
    s = surface_setup
    r = await client.get(_url(s["org"].id, s["scan"].id), headers=s["headers"])
    assert r.status_code == 200
    body = r.json()
    assert body["total_discovered"] == 0
    assert body["live"] == 0
    assert body["dead"] == 0
    assert body["subdomains"] == []
    assert body["root_domain"] == "https://shop.example.com"


# ============================================================ 6. timeout bucketing (Y1)


@pytest.mark.asyncio
async def test_get_attack_surface_timeout_status_bucketed_as_dead(
    surface_setup, db_session, client
):
    """Y1: timeout rows count toward `dead` at the aggregate, but the
    per-subdomain entry preserves the true `timeout` status."""
    s = surface_setup
    await _seed_attack_surface(
        db_session,
        s["scan"],
        s["org"],
        full_url="https://live.example.com",
        status=SubdomainStatus.LIVE,
    )
    await _seed_attack_surface(
        db_session,
        s["scan"],
        s["org"],
        full_url="https://dead.example.com",
        status=SubdomainStatus.DEAD,
        status_code=None,
    )
    await _seed_attack_surface(
        db_session,
        s["scan"],
        s["org"],
        full_url="https://slow.example.com",
        status=SubdomainStatus.TIMEOUT,
        status_code=None,
    )

    r = await client.get(_url(s["org"].id, s["scan"].id), headers=s["headers"])
    assert r.status_code == 200
    body = r.json()
    assert body["total_discovered"] == 3
    assert body["live"] == 1
    assert body["dead"] == 2  # dead + timeout bucketed

    by_url = {entry["url"]: entry for entry in body["subdomains"]}
    assert by_url["https://slow.example.com"]["status"] == "timeout"  # fidelity


# ============================================================ 7-8. vulnerability_count (Y2)


@pytest.mark.asyncio
async def test_get_attack_surface_vulnerability_count_zero_pre_m9(
    surface_setup, db_session, client
):
    """Y2: with a populated surface but an empty vulnerabilities table
    (pre-M9 AI pipeline), every vulnerability_count is 0."""
    s = surface_setup
    await _seed_attack_surface(
        db_session,
        s["scan"],
        s["org"],
        full_url="https://api.example.com",
        status=SubdomainStatus.LIVE,
    )
    r = await client.get(_url(s["org"].id, s["scan"].id), headers=s["headers"])
    assert r.status_code == 200
    body = r.json()
    assert body["subdomains"][0]["vulnerability_count"] == 0


@pytest.mark.asyncio
async def test_get_attack_surface_vulnerability_count_with_vulnerabilities(
    surface_setup, db_session, client
):
    """Y2 structural correctness (post-M9 shape): vulnerability_count
    reflects vulnerabilities-table rows joined on target_url == full_url."""
    s = surface_setup
    await _seed_attack_surface(
        db_session,
        s["scan"],
        s["org"],
        full_url="https://api.example.com",
        status=SubdomainStatus.LIVE,
    )
    await _seed_attack_surface(
        db_session,
        s["scan"],
        s["org"],
        full_url="https://www.example.com",
        status=SubdomainStatus.LIVE,
    )
    # two vulnerabilities on api, zero on www
    await _seed_vulnerability(
        db_session,
        s["scan"],
        s["org"],
        s["project"],
        target_url="https://api.example.com",
    )
    await _seed_vulnerability(
        db_session,
        s["scan"],
        s["org"],
        s["project"],
        target_url="https://api.example.com",
    )

    r = await client.get(_url(s["org"].id, s["scan"].id), headers=s["headers"])
    assert r.status_code == 200
    body = r.json()
    by_url = {entry["url"]: entry for entry in body["subdomains"]}
    assert by_url["https://api.example.com"]["vulnerability_count"] == 2
    assert by_url["https://www.example.com"]["vulnerability_count"] == 0
