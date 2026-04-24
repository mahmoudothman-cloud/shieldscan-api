"""End-to-end tests for /v1/orgs/{org_id}/projects/* (Task 3.1)."""

from __future__ import annotations

from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from sqlalchemy import select

from app.models.identity import Membership, MembershipRole, Organization, User
from app.models.projects import Project
from app.services.auth import create_access_token, hash_password
from app.services.projects import extract_root_domain
from tests.conftest import use_org


@pytest_asyncio.fixture
async def project_owner(client, db_session):
    """Org A admin: yields (org, user, jwt_headers, api_key_headers)."""
    org = Organization(name="Owner Org", slug=f"ownerorg-{uuid4().hex[:8]}")
    db_session.add(org)
    await db_session.flush()
    await use_org(db_session, org.id)
    user = User(
        email=f"owner-{uuid4().hex[:6]}@t.co",
        hashed_password=hash_password("OwnerPass-1"),
        full_name="Owner",
        email_verified=True,
    )
    db_session.add(user)
    await db_session.flush()
    db_session.add(
        Membership(user_id=user.id, organization_id=org.id, role=MembershipRole.ADMIN)
    )
    await db_session.commit()
    headers = {"Authorization": f"Bearer {create_access_token(sub=str(user.id))}"}
    return org, user, headers


@pytest_asyncio.fixture
async def other_org_admin(db_session):
    """Org B admin: yields (org, user, jwt_headers). Distinct from
    project_owner — used for cross-tenant access tests."""
    org = Organization(name="Other Org", slug=f"otherorg-{uuid4().hex[:8]}")
    db_session.add(org)
    await db_session.flush()
    await use_org(db_session, org.id)
    user = User(
        email=f"other-{uuid4().hex[:6]}@t.co",
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
    headers = {"Authorization": f"Bearer {create_access_token(sub=str(user.id))}"}
    return org, user, headers


def _create_payload(name="Site", target="https://example.com"):
    return {"name": name, "target_url": target}


# =============================================================== extract_root_domain (helper unit tests)


def test_extract_root_domain_plain_url():
    assert extract_root_domain("https://www.example.com/path") == "example.com"
    assert extract_root_domain("https://example.com") == "example.com"


def test_extract_root_domain_complex_cases():
    # Multi-segment TLD via PSL.
    assert extract_root_domain("https://api.example.co.uk") == "example.co.uk"
    # Port preserved at parse time, stripped from hostname.
    assert extract_root_domain("https://app.example.com:8443") == "example.com"
    # IP literal — passthrough.
    assert extract_root_domain("https://192.168.1.1") == "192.168.1.1"


# =============================================================== POST (create)


@pytest.mark.asyncio
async def test_create_project_happy_path(client, project_owner, db_session):
    org, _, headers = project_owner
    r = await client.post(
        f"/v1/orgs/{org.id}/projects",
        json=_create_payload(name="My Site", target="https://example.com"),
        headers=headers,
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["name"] == "My Site"
    assert body["target_url"] == "https://example.com"
    assert body["root_domain"] == "example.com"
    assert body["domain_verified"] is False
    # verification_token is on the response (Task 3.1 §H decision #2).
    assert isinstance(body["verification_token"], str)
    assert len(body["verification_token"]) > 0
    # Persisted.
    rows = (await db_session.execute(select(Project))).scalars().all()
    assert len(rows) == 1


@pytest.mark.asyncio
async def test_create_project_derives_root_domain_from_target(
    client, project_owner
):
    """root_domain is server-derived; clients can't override it."""
    org, _, headers = project_owner
    r = await client.post(
        f"/v1/orgs/{org.id}/projects",
        json=_create_payload(target="https://api.app.example.co.uk/v1"),
        headers=headers,
    )
    assert r.status_code == 201
    assert r.json()["root_domain"] == "example.co.uk"


@pytest.mark.asyncio
async def test_create_project_rejects_http_target_url(
    client, project_owner
):
    """HTTPS-only — security requirement (no plaintext scan target)."""
    org, _, headers = project_owner
    r = await client.post(
        f"/v1/orgs/{org.id}/projects",
        json=_create_payload(target="http://insecure.example.com"),
        headers=headers,
    )
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_create_project_rejects_missing_target_url(
    client, project_owner
):
    org, _, headers = project_owner
    r = await client.post(
        f"/v1/orgs/{org.id}/projects",
        json={"name": "missing"},  # no target_url
        headers=headers,
    )
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_create_project_allows_duplicate_names_in_same_org(
    client, project_owner, db_session
):
    """Design invariant: no UNIQUE on (organization_id, name).
    Two projects with the same name in one org both succeed.

    If this test fails: someone added a uniqueness constraint at
    schema or DB level. That's a UX trade-off (forces unique names)
    that should be a deliberate decision, not a refactor side effect.
    See Task 3.1 §H decision #3.
    """
    org, _, headers = project_owner
    p = _create_payload(name="Dupe Name")
    r1 = await client.post(f"/v1/orgs/{org.id}/projects", json=p, headers=headers)
    r2 = await client.post(f"/v1/orgs/{org.id}/projects", json=p, headers=headers)
    assert r1.status_code == 201
    assert r2.status_code == 201
    rows = (await db_session.execute(select(Project))).scalars().all()
    assert len(rows) == 2


# =============================================================== GET (list)


@pytest.mark.asyncio
async def test_list_projects_happy_path(client, project_owner):
    org, _, headers = project_owner
    for i in range(3):
        await client.post(
            f"/v1/orgs/{org.id}/projects",
            json=_create_payload(name=f"P{i}"),
            headers=headers,
        )
    r = await client.get(f"/v1/orgs/{org.id}/projects", headers=headers)
    assert r.status_code == 200
    body = r.json()
    assert len(body["items"]) == 3
    assert body["pagination"]["total"] == 3


@pytest.mark.asyncio
async def test_list_projects_pagination(client, project_owner):
    """Page 2 with per_page=2 returns the third item, pagination meta
    correct, has_prev=True, has_next=False."""
    org, _, headers = project_owner
    for i in range(3):
        await client.post(
            f"/v1/orgs/{org.id}/projects",
            json=_create_payload(name=f"P{i}"),
            headers=headers,
        )
    r = await client.get(
        f"/v1/orgs/{org.id}/projects?page=2&per_page=2", headers=headers
    )
    assert r.status_code == 200
    body = r.json()
    assert len(body["items"]) == 1
    p = body["pagination"]
    assert p == {
        "page": 2,
        "per_page": 2,
        "total": 3,
        "total_pages": 2,
        "has_next": False,
        "has_prev": True,
    }


@pytest.mark.asyncio
async def test_list_projects_per_page_cap(client, project_owner):
    """per_page > 100 → 422."""
    org, _, headers = project_owner
    r = await client.get(
        f"/v1/orgs/{org.id}/projects?per_page=101", headers=headers
    )
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_list_projects_page_zero_rejected(client, project_owner):
    """page=0 → 422 (Task 3.1 watch item)."""
    org, _, headers = project_owner
    r = await client.get(
        f"/v1/orgs/{org.id}/projects?page=0", headers=headers
    )
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_list_projects_page_beyond_total_returns_empty(
    client, project_owner
):
    """page > total_pages returns 200 with empty items + correct meta
    (NOT 404). Task 3.1 watch item."""
    org, _, headers = project_owner
    await client.post(
        f"/v1/orgs/{org.id}/projects",
        json=_create_payload(name="only"),
        headers=headers,
    )
    r = await client.get(
        f"/v1/orgs/{org.id}/projects?page=99&per_page=10", headers=headers
    )
    assert r.status_code == 200
    body = r.json()
    assert body["items"] == []
    assert body["pagination"]["total"] == 1
    assert body["pagination"]["has_next"] is False


@pytest.mark.asyncio
async def test_list_projects_default_excludes_archived(
    client, project_owner, db_session
):
    org, _, headers = project_owner
    # Two projects; archive one.
    r1 = await client.post(
        f"/v1/orgs/{org.id}/projects",
        json=_create_payload(name="active"),
        headers=headers,
    )
    r2 = await client.post(
        f"/v1/orgs/{org.id}/projects",
        json=_create_payload(name="to-archive"),
        headers=headers,
    )
    archived_id = r2.json()["id"]
    await client.delete(
        f"/v1/orgs/{org.id}/projects/{archived_id}", headers=headers
    )

    r = await client.get(f"/v1/orgs/{org.id}/projects", headers=headers)
    body = r.json()
    assert len(body["items"]) == 1
    assert body["items"][0]["name"] == "active"
    assert body["pagination"]["total"] == 1


@pytest.mark.asyncio
async def test_list_projects_archived_true_includes_archived(
    client, project_owner
):
    org, _, headers = project_owner
    r1 = await client.post(
        f"/v1/orgs/{org.id}/projects",
        json=_create_payload(name="active"),
        headers=headers,
    )
    r2 = await client.post(
        f"/v1/orgs/{org.id}/projects",
        json=_create_payload(name="archived"),
        headers=headers,
    )
    await client.delete(
        f"/v1/orgs/{org.id}/projects/{r2.json()['id']}", headers=headers
    )
    r = await client.get(
        f"/v1/orgs/{org.id}/projects?archived=true", headers=headers
    )
    body = r.json()
    assert len(body["items"]) == 2


@pytest.mark.asyncio
async def test_list_projects_cross_tenant_returns_404(
    client, project_owner, other_org_admin
):
    """Org B admin trying path /v1/orgs/{org_a.id}/projects must 404.
    require_org_membership rejects path-vs-identity mismatch."""
    org_a, _, _ = project_owner
    _, _, headers_b = other_org_admin
    r = await client.get(
        f"/v1/orgs/{org_a.id}/projects", headers=headers_b
    )
    assert r.status_code == 404
    assert r.json()["detail"] == "not_found"


# =============================================================== GET single


@pytest.mark.asyncio
async def test_get_project_happy_path(client, project_owner):
    org, _, headers = project_owner
    create_r = await client.post(
        f"/v1/orgs/{org.id}/projects",
        json=_create_payload(name="get-me"),
        headers=headers,
    )
    pid = create_r.json()["id"]
    r = await client.get(
        f"/v1/orgs/{org.id}/projects/{pid}", headers=headers
    )
    assert r.status_code == 200
    assert r.json()["name"] == "get-me"


@pytest.mark.asyncio
async def test_get_project_nonexistent_returns_404(
    client, project_owner
):
    org, _, headers = project_owner
    r = await client.get(
        f"/v1/orgs/{org.id}/projects/{uuid4()}", headers=headers
    )
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_get_archived_project_returns_200(client, project_owner):
    """Archived projects are reversible state. GET returns 200 with
    archived_at populated, NOT 404 (Task 3.1 §6 decision)."""
    org, _, headers = project_owner
    r1 = await client.post(
        f"/v1/orgs/{org.id}/projects",
        json=_create_payload(name="will-archive"),
        headers=headers,
    )
    pid = r1.json()["id"]
    await client.delete(
        f"/v1/orgs/{org.id}/projects/{pid}", headers=headers
    )
    r = await client.get(
        f"/v1/orgs/{org.id}/projects/{pid}", headers=headers
    )
    assert r.status_code == 200
    assert r.json()["archived_at"] is not None


# =============================================================== PATCH


@pytest.mark.asyncio
async def test_patch_project_partial_update(client, project_owner):
    org, _, headers = project_owner
    create = await client.post(
        f"/v1/orgs/{org.id}/projects",
        json=_create_payload(name="orig"),
        headers=headers,
    )
    pid = create.json()["id"]
    r = await client.patch(
        f"/v1/orgs/{org.id}/projects/{pid}",
        json={"name": "renamed"},
        headers=headers,
    )
    assert r.status_code == 200
    assert r.json()["name"] == "renamed"
    # target_url unchanged.
    assert r.json()["target_url"] == "https://example.com"


@pytest.mark.asyncio
async def test_patch_project_immutable_fields_rejected(
    client, project_owner
):
    """extra='forbid' on ProjectUpdateRequest blocks unknown fields."""
    org, _, headers = project_owner
    create = await client.post(
        f"/v1/orgs/{org.id}/projects",
        json=_create_payload(name="orig"),
        headers=headers,
    )
    pid = create.json()["id"]
    r = await client.patch(
        f"/v1/orgs/{org.id}/projects/{pid}",
        json={"organization_id": str(uuid4())},  # immutable
        headers=headers,
    )
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_patch_target_url_same_domain_keeps_verification(
    client, project_owner, db_session
):
    """target_url change WITHIN the same root_domain (path/port only)
    must NOT reset domain_verified or rotate the token."""
    org, _, headers = project_owner
    create = await client.post(
        f"/v1/orgs/{org.id}/projects",
        json=_create_payload(target="https://example.com/v1"),
        headers=headers,
    )
    pid = UUID(create.json()["id"])
    original_token = create.json()["verification_token"]

    # Manually flip domain_verified to verified (simulates Task 3.2's
    # successful verify; we don't have that endpoint yet).
    project = (
        await db_session.execute(select(Project).where(Project.id == pid))
    ).scalar_one()
    project.domain_verified = True
    await db_session.commit()

    # PATCH target_url to a different path on the SAME domain.
    r = await client.patch(
        f"/v1/orgs/{org.id}/projects/{pid}",
        json={"target_url": "https://example.com/v2/api"},
        headers=headers,
    )
    assert r.status_code == 200
    body = r.json()
    assert body["target_url"] == "https://example.com/v2/api"
    assert body["root_domain"] == "example.com"
    assert body["domain_verified"] is True  # NOT reset
    assert body["verification_token"] == original_token  # NOT rotated


@pytest.mark.asyncio
async def test_patch_target_url_different_domain_resets_verification(
    client, project_owner, db_session
):
    """target_url change that alters root_domain auto-resets
    domain_verified=False AND mints a new verification_token (per
    DRIFT-LOG 2026-04-23 entry on auto-reset)."""
    org, _, headers = project_owner
    create = await client.post(
        f"/v1/orgs/{org.id}/projects",
        json=_create_payload(target="https://example.com/v1"),
        headers=headers,
    )
    pid = UUID(create.json()["id"])
    original_token = create.json()["verification_token"]

    project = (
        await db_session.execute(select(Project).where(Project.id == pid))
    ).scalar_one()
    project.domain_verified = True
    await db_session.commit()

    # PATCH to a DIFFERENT root domain.
    r = await client.patch(
        f"/v1/orgs/{org.id}/projects/{pid}",
        json={"target_url": "https://different.org/api"},
        headers=headers,
    )
    assert r.status_code == 200
    body = r.json()
    assert body["root_domain"] == "different.org"
    assert body["domain_verified"] is False  # RESET
    assert body["verification_token"] != original_token  # ROTATED


# =============================================================== DELETE


@pytest.mark.asyncio
async def test_delete_project_soft_deletes(client, project_owner, db_session):
    org, _, headers = project_owner
    create = await client.post(
        f"/v1/orgs/{org.id}/projects",
        json=_create_payload(name="delete-me"),
        headers=headers,
    )
    pid = UUID(create.json()["id"])
    r = await client.delete(
        f"/v1/orgs/{org.id}/projects/{pid}", headers=headers
    )
    assert r.status_code == 204
    project = (
        await db_session.execute(select(Project).where(Project.id == pid))
    ).scalar_one()
    assert project.archived_at is not None  # soft-deleted, not hard-deleted


@pytest.mark.asyncio
async def test_delete_already_archived_returns_410(
    client, project_owner
):
    org, _, headers = project_owner
    create = await client.post(
        f"/v1/orgs/{org.id}/projects",
        json=_create_payload(name="double-delete"),
        headers=headers,
    )
    pid = create.json()["id"]
    r1 = await client.delete(
        f"/v1/orgs/{org.id}/projects/{pid}", headers=headers
    )
    assert r1.status_code == 204
    r2 = await client.delete(
        f"/v1/orgs/{org.id}/projects/{pid}", headers=headers
    )
    assert r2.status_code == 410
    assert r2.json()["detail"] == "project_already_archived"


@pytest.mark.asyncio
async def test_delete_cross_tenant_returns_404(
    client, project_owner, other_org_admin
):
    """Cross-tenant delete attempt → 404 (NOT 403 — no existence
    leak)."""
    org_a, _, headers_a = project_owner
    create = await client.post(
        f"/v1/orgs/{org_a.id}/projects",
        json=_create_payload(name="a-only"),
        headers=headers_a,
    )
    pid = create.json()["id"]
    _, _, headers_b = other_org_admin
    org_b, _, _ = other_org_admin
    r = await client.delete(
        f"/v1/orgs/{org_b.id}/projects/{pid}", headers=headers_b
    )
    assert r.status_code == 404


# =============================================================== require_org_membership dep


@pytest.mark.asyncio
async def test_require_org_membership_path_mismatch_returns_404(
    client, project_owner, other_org_admin
):
    """Org B admin trying path with Org A's id → 404 (path-vs-identity
    mismatch wins over project-existence check)."""
    org_a, _, _ = project_owner
    _, _, headers_b = other_org_admin
    r = await client.get(
        f"/v1/orgs/{org_a.id}/projects/{uuid4()}", headers=headers_b
    )
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_require_org_membership_unauthenticated_returns_401(
    client, project_owner
):
    org, _, _ = project_owner
    r = await client.get(f"/v1/orgs/{org.id}/projects")
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_require_org_membership_jwt_only_rejects_api_key(
    client, project_owner, db_session
):
    """DELETE uses jwt_only=True — API key credentials get 403."""
    import hashlib

    from app.models.identity import APIKey

    org, _, headers = project_owner
    # Create a project as JWT admin.
    create = await client.post(
        f"/v1/orgs/{org.id}/projects",
        json=_create_payload(name="api-key-test"),
        headers=headers,
    )
    pid = create.json()["id"]

    # Mint an API key for this org and try to DELETE with it.
    plaintext = f"ss_live_test_{uuid4().hex[:24]}"
    db_session.add(
        APIKey(
            organization_id=org.id,
            name="key",
            key_prefix=plaintext[:12],
            key_hash=hashlib.sha256(plaintext.encode()).hexdigest(),
        )
    )
    await db_session.commit()

    r = await client.delete(
        f"/v1/orgs/{org.id}/projects/{pid}",
        headers={"Authorization": f"Bearer {plaintext}"},
    )
    assert r.status_code == 403
    assert r.json()["detail"] == "api_key_insufficient_for_operation"
