"""End-to-end tests for POST /v1/orgs/{org}/projects/{pid}/scans (Task 4.3).

19 tests covering the scan-creation contract:

  Happy paths (5):
   1. full_web → 8 ScanJobs + 8 queue items, status=queued
   2. quick → 4 ScanJobs
   3. mobile (with mobile_upload_id) → 1 mobsf job
   4. api → 3 ScanJobs
   5. container → succeeds even when project is unverified

  Validation (8):
   6. mobile scan without mobile_upload_id → 422
   7. non-mobile scan with mobile_upload_id → 422
   8. PUBLIC scan_type → 422 at route layer
   9. invalid priority → 422
  10. extra fields (callback_url etc.) → 422
  11. config too large (>64 KB serialized) → 422
  12. config too deep (>5 levels) → 422
  13. config too many keys (>50 at root) → 422

  Auth + tenant (3):
  14. unauthenticated → 401
  15. cross-tenant project (other org's pid under caller's org_id) → 404
  16. mobile_upload_id from different org → 404 (existence-hiding)

  Domain-verified gate (1):
  17. unverified project + full_web → 403 domain_not_verified

  Eager-load + audit pins (2):
  18. eager-load: orchestrator builds payload without MissingGreenlet
  19. exactly one SCAN_DISPATCHED audit row (no duplicate from route)
"""

from __future__ import annotations

import json
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from sqlalchemy import select

from app.models.audit import AuditLog
from app.models.identity import Membership, MembershipRole, Organization, User
from app.models.mobile import MobilePlatform, MobileUpload
from app.models.projects import Project
from app.models.scans import Scan, ScanJob, ScanType
from app.services.auth import create_access_token, hash_password
from tests.conftest import use_org


# ---------------------------------------------------------------- fixtures


@pytest_asyncio.fixture
async def project_setup(client, db_session):
    """Org + admin + verified project + JWT headers + a mobile upload
    in the same org. Returns dict of handles."""
    org = Organization(name="Scan Org", slug=f"scan-{uuid4().hex[:8]}")
    db_session.add(org)
    await db_session.flush()
    await use_org(db_session, org.id)

    user = User(
        email=f"s-{uuid4().hex[:6]}@t.co",
        hashed_password=hash_password("ScanPass-1"),
        full_name="S",
        email_verified=True,
    )
    db_session.add(user)
    await db_session.flush()
    db_session.add(
        Membership(user_id=user.id, organization_id=org.id, role=MembershipRole.ADMIN)
    )

    project = Project(
        organization_id=org.id,
        name="ScanApp",
        target_url="https://scan.example.com",
        root_domain="example.com",
        domain_verified=True,
    )
    db_session.add(project)
    await db_session.flush()

    upload = MobileUpload(
        organization_id=org.id,
        project_id=project.id,
        uploaded_by=user.id,
        filename="app.apk",
        file_extension=".apk",
        file_size_bytes=2048,
        platform=MobilePlatform.ANDROID,
        r2_key=f"mobile-uploads/{org.id}/{project.id}/{uuid4()}.apk",
    )
    db_session.add(upload)
    await db_session.commit()
    await db_session.refresh(project)
    await db_session.refresh(upload)

    return {
        "org": org,
        "project": project,
        "user": user,
        "upload": upload,
        "headers": {"Authorization": f"Bearer {create_access_token(sub=str(user.id))}"},
    }


@pytest_asyncio.fixture
async def unverified_project(client, db_session):
    """Org + admin + UNVERIFIED project. For domain_verified gate tests."""
    org = Organization(name="UV Org", slug=f"uv-{uuid4().hex[:8]}")
    db_session.add(org)
    await db_session.flush()
    await use_org(db_session, org.id)

    user = User(
        email=f"uv-{uuid4().hex[:6]}@t.co",
        hashed_password=hash_password("UVPass-1"),
        full_name="UV",
        email_verified=True,
    )
    db_session.add(user)
    await db_session.flush()
    db_session.add(
        Membership(user_id=user.id, organization_id=org.id, role=MembershipRole.ADMIN)
    )
    project = Project(
        organization_id=org.id,
        name="UVApp",
        target_url="https://uv.example.com",
        root_domain="example.com",
        domain_verified=False,
    )
    db_session.add(project)
    await db_session.commit()
    await db_session.refresh(project)
    return {
        "org": org,
        "project": project,
        "user": user,
        "headers": {"Authorization": f"Bearer {create_access_token(sub=str(user.id))}"},
    }


@pytest_asyncio.fixture
async def other_org_project(db_session):
    """Second org with its own project + mobile upload — used for
    cross-tenant tests."""
    org = Organization(name="Other S Org", slug=f"oth-{uuid4().hex[:8]}")
    db_session.add(org)
    await db_session.flush()
    await use_org(db_session, org.id)
    user = User(
        email=f"oth-{uuid4().hex[:6]}@t.co",
        hashed_password=hash_password("OthPass-1"),
        full_name="Oth",
        email_verified=True,
    )
    db_session.add(user)
    await db_session.flush()
    db_session.add(
        Membership(user_id=user.id, organization_id=org.id, role=MembershipRole.ADMIN)
    )
    project = Project(
        organization_id=org.id,
        name="OtherApp",
        target_url="https://oth.example.com",
        root_domain="example.com",
        domain_verified=True,
    )
    db_session.add(project)
    await db_session.flush()
    upload = MobileUpload(
        organization_id=org.id,
        project_id=project.id,
        uploaded_by=user.id,
        filename="other.apk",
        file_extension=".apk",
        file_size_bytes=512,
        platform=MobilePlatform.ANDROID,
        r2_key=f"mobile-uploads/{org.id}/{project.id}/{uuid4()}.apk",
    )
    db_session.add(upload)
    await db_session.commit()
    await db_session.refresh(project)
    await db_session.refresh(upload)
    return {"org": org, "project": project, "upload": upload}


def _url(s):
    return f"/v1/orgs/{s['org'].id}/projects/{s['project'].id}/scans"


# ============================================================ 1-5. happy paths


@pytest.mark.asyncio
async def test_create_full_web_scan_creates_8_jobs(project_setup, client, db_session, fake_redis):
    s = project_setup
    r = await client.post(
        _url(s),
        json={"scan_type": "full_web"},
        headers=s["headers"],
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["status"] == "queued"
    assert body["scan_type"] == "full_web"
    assert len(body["jobs"]) == 8
    # Each job has id, engine, idempotency_key.
    for job in body["jobs"]:
        UUID(job["id"])
        assert job["engine"]
        assert ":" in job["idempotency_key"]

    # 8 queue items dispatched to 'normal' priority.
    queued = []
    for _ in range(8):
        item = await fake_redis.brpop("shieldscan:queue:normal", timeout=1)
        assert item is not None
        queued.append(json.loads(item[1]))
    assert {q["engine"] for q in queued} == {j["engine"] for j in body["jobs"]}


@pytest.mark.asyncio
async def test_create_quick_scan_creates_4_jobs(project_setup, client, fake_redis):
    s = project_setup
    r = await client.post(
        _url(s),
        json={"scan_type": "quick"},
        headers=s["headers"],
    )
    assert r.status_code == 201, r.text
    assert len(r.json()["jobs"]) == 4


@pytest.mark.asyncio
async def test_create_mobile_scan_with_upload_id_succeeds(project_setup, client, fake_redis):
    s = project_setup
    r = await client.post(
        _url(s),
        json={"scan_type": "mobile", "mobile_upload_id": str(s["upload"].id)},
        headers=s["headers"],
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert len(body["jobs"]) == 1
    assert body["jobs"][0]["engine"] == "mobsf"
    assert body["mobile_upload_id"] == str(s["upload"].id)


@pytest.mark.asyncio
async def test_create_api_scan_creates_3_jobs(project_setup, client, fake_redis):
    s = project_setup
    r = await client.post(
        _url(s),
        json={"scan_type": "api"},
        headers=s["headers"],
    )
    assert r.status_code == 201, r.text
    assert len(r.json()["jobs"]) == 3


@pytest.mark.asyncio
async def test_create_container_scan_does_not_require_domain_verified(
    unverified_project, client, fake_redis
):
    """Container scans bypass the domain-verified gate. The image is
    the bound asset; project.target_url is informational."""
    s = unverified_project
    r = await client.post(
        _url(s),
        json={"scan_type": "container"},
        headers=s["headers"],
    )
    assert r.status_code == 201, r.text
    assert r.json()["scan_type"] == "container"


# ============================================================ 6-13. validation


@pytest.mark.asyncio
async def test_mobile_scan_without_upload_id_returns_422(project_setup, client):
    s = project_setup
    r = await client.post(
        _url(s),
        json={"scan_type": "mobile"},
        headers=s["headers"],
    )
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_non_mobile_scan_with_upload_id_returns_422(project_setup, client):
    s = project_setup
    r = await client.post(
        _url(s),
        json={"scan_type": "full_web", "mobile_upload_id": str(s["upload"].id)},
        headers=s["headers"],
    )
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_public_scan_type_rejected_at_route_with_422(project_setup, client):
    """Public scans live on a different endpoint per ADDENDUM-CRITICAL-5
    §2.4. Rejected at the Pydantic layer before reaching the orchestrator
    (which has its own UnsupportedScanTypeError as defense-in-depth)."""
    s = project_setup
    r = await client.post(
        _url(s),
        json={"scan_type": "public"},
        headers=s["headers"],
    )
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_invalid_priority_returns_422(project_setup, client):
    s = project_setup
    r = await client.post(
        _url(s),
        json={"scan_type": "quick", "priority": "URGENT"},
        headers=s["headers"],
    )
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_extra_fields_rejected_422(project_setup, client):
    """ConfigDict(extra='forbid') on ScanCreateRequest catches stale
    plan/SPEC-literal fields like callback_url, dast_config,
    mobile_config (the request body uses mobile_upload_id instead)."""
    s = project_setup
    r = await client.post(
        _url(s),
        json={
            "scan_type": "quick",
            "callback_url": "https://example.com/webhook",
        },
        headers=s["headers"],
    )
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_config_oversized_returns_422(project_setup, client):
    """Shape-bounds DoS guard. Real json.dumps to ensure the rejection
    triggers on serialized size, not raw dict character count."""
    s = project_setup
    # 70 KB of distinct keys to defeat any silly minification.
    big = {f"key_{i}": "x" * 100 for i in range(700)}
    assert len(json.dumps(big)) > 64 * 1024
    # But within 50-key limit per a different guard? No — 700 keys would also trip
    # the keys guard. Build a shape that violates ONLY the size guard:
    # one top-level key whose value is a long string.
    big = {"data": "x" * (70 * 1024)}
    assert len(json.dumps(big)) > 64 * 1024
    r = await client.post(
        _url(s),
        json={"scan_type": "quick", "config": big},
        headers=s["headers"],
    )
    assert r.status_code == 422
    assert "config_too_large" in r.text


@pytest.mark.asyncio
async def test_config_too_deep_returns_422(project_setup, client):
    s = project_setup
    # depth 6 nested: a → a → a → a → a → a → leaf
    deep = {}
    cur = deep
    for _ in range(6):
        cur["a"] = {}
        cur = cur["a"]
    cur["leaf"] = 1
    r = await client.post(
        _url(s),
        json={"scan_type": "quick", "config": deep},
        headers=s["headers"],
    )
    assert r.status_code == 422
    assert "config_too_deep" in r.text


@pytest.mark.asyncio
async def test_config_too_many_keys_returns_422(project_setup, client):
    s = project_setup
    many = {f"k{i}": i for i in range(51)}
    r = await client.post(
        _url(s),
        json={"scan_type": "quick", "config": many},
        headers=s["headers"],
    )
    assert r.status_code == 422
    assert "config_too_many_keys" in r.text


# ============================================================ 14-16. auth + tenant


@pytest.mark.asyncio
async def test_unauthenticated_returns_401(project_setup, client):
    s = project_setup
    r = await client.post(_url(s), json={"scan_type": "quick"})
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_cross_tenant_project_returns_404(project_setup, other_org_project, client):
    """Caller's org_id in path with another org's project_id should
    404 (existence hiding) — caller doesn't belong to the project's
    org. The require_org_membership dep catches the org_id mismatch
    before reaching the project lookup; 404 either way."""
    s = project_setup
    other = other_org_project
    url = f"/v1/orgs/{s['org'].id}/projects/{other['project'].id}/scans"
    r = await client.post(url, json={"scan_type": "quick"}, headers=s["headers"])
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_mobile_upload_from_different_org_returns_404(
    project_setup, other_org_project, client
):
    """Existence-hiding: mobile_upload_id from another tenant returns
    404, not 403, to prevent enumeration of cross-tenant upload ids."""
    s = project_setup
    other_upload = other_org_project["upload"]
    r = await client.post(
        _url(s),
        json={"scan_type": "mobile", "mobile_upload_id": str(other_upload.id)},
        headers=s["headers"],
    )
    assert r.status_code == 404


# ============================================================ 17. domain-verified gate


@pytest.mark.asyncio
async def test_unverified_project_full_web_returns_403_domain_not_verified(
    unverified_project, client
):
    s = unverified_project
    r = await client.post(
        _url(s),
        json={"scan_type": "full_web"},
        headers=s["headers"],
    )
    assert r.status_code == 403
    assert r.json()["detail"] == "domain_not_verified"


# ============================================================ 18. eager-load regression guard


@pytest.mark.asyncio
async def test_create_scan_does_not_trigger_lazy_load_missinggreenlet(
    project_setup, client, fake_redis
):
    """Regression guard for the in-memory scan.project attach.

    The orchestrator's _build_job_payload accesses scan.project
    synchronously. Without the route's `scan.project = project`
    in-memory attach, SQLAlchemy lazy-load would trigger and raise
    MissingGreenlet in async context.

    Indirect proof: a successful 201 response means the orchestrator
    built the payload without a greenlet error. If a future engineer
    drops the in-memory attach (or swaps to a flow that doesn't load
    the project), the orchestrator would raise and this test would
    surface it as a 500.
    """
    s = project_setup
    r = await client.post(
        _url(s),
        json={"scan_type": "quick"},
        headers=s["headers"],
    )
    assert r.status_code == 201, r.text
    # Payload pulled scan.project.target_url successfully:
    item = await fake_redis.brpop("shieldscan:queue:normal", timeout=1)
    payload = json.loads(item[1])
    assert payload["target"]["url"] == s["project"].target_url


# ============================================================ 19. exactly one SCAN_DISPATCHED audit


@pytest.mark.asyncio
async def test_create_scan_emits_exactly_one_scan_dispatched_audit(
    project_setup, client, db_session, fake_redis
):
    """The route MUST NOT emit its own audit row alongside the
    orchestrator's. One dispatch event = one audit row. Pin to
    catch a future "helpful" route-level audit duplication."""
    s = project_setup
    r = await client.post(
        _url(s),
        json={"scan_type": "quick"},
        headers=s["headers"],
    )
    assert r.status_code == 201
    scan_id = UUID(r.json()["id"])

    audits = (
        await db_session.execute(
            select(AuditLog).where(
                AuditLog.action == "scan.dispatched",
                AuditLog.resource_id == scan_id,
            )
        )
    ).scalars().all()
    assert len(audits) == 1, (
        f"expected exactly 1 SCAN_DISPATCHED audit row, got {len(audits)}"
    )
    a = audits[0]
    assert a.actor_id == s["user"].id
    assert a.organization_id == s["org"].id
    assert a.details["scan_type"] == "quick"
    assert a.details["job_count"] == 4
