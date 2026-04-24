"""End-to-end tests for /v1/auth/api-keys/* — Task 2.4, Commit 2."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import select

from app.models.audit import AuditLog
from app.models.identity import APIKey, Membership, MembershipRole, Organization, User
from app.schemas.api_keys import APIKeyCreatedResponse, APIKeySummary
from app.services.auth import create_access_token, hash_password
from tests.conftest import use_org


# ---------------------------------------------------------------- helpers


async def _make_org_and_admin(db_session, *, slug_suffix: str = ""):
    """Create Org + admin User + Membership. Returns (org, user)."""
    org = Organization(
        name=f"Org K {slug_suffix}",
        slug=f"orgk-{slug_suffix}-{uuid4().hex[:6]}",
    )
    db_session.add(org)
    await db_session.flush()
    await use_org(db_session, org.id)
    user = User(
        email=f"admin-{uuid4().hex[:6]}@t.co",
        hashed_password=hash_password("AdminPass1!"),
        full_name="Admin",
        email_verified=True,
    )
    db_session.add(user)
    await db_session.flush()
    db_session.add(
        Membership(user_id=user.id, organization_id=org.id, role=MembershipRole.ADMIN)
    )
    await db_session.commit()
    return org, user


def _jwt_headers(user) -> dict[str, str]:
    return {"Authorization": f"Bearer {create_access_token(sub=str(user.id))}"}


@pytest_asyncio.fixture
async def admin_of_existing(client, existing_user, db_session):
    """Reuse the existing_user fixture but promote them to admin of
    their org and mark email_verified."""
    user, _ = existing_user
    user.email_verified = True
    # existing_user's orchestrator already created a Membership with
    # role=ADMIN. Confirm the assumption.
    result = await db_session.execute(
        select(Membership.role).where(Membership.user_id == user.id)
    )
    assert result.scalar_one() == MembershipRole.ADMIN
    return user


# ---------------------------------------------------------------- create


@pytest.mark.asyncio
async def test_create_api_key_happy_path(client, admin_of_existing, db_session):
    r = await client.post(
        "/v1/auth/api-keys",
        json={"name": "CI token"},
        headers=_jwt_headers(admin_of_existing),
    )
    assert r.status_code == 201, r.text
    body = r.json()
    # The create response INCLUDES plaintext_key — visible exactly once.
    assert "plaintext_key" in body
    assert body["plaintext_key"].startswith("ss_live_")
    assert len(body["plaintext_key"]) == 48
    assert body["key_prefix"] == body["plaintext_key"][:12]
    assert body["name"] == "CI token"

    # Row persisted with hash (not plaintext).
    rows = (await db_session.execute(select(APIKey))).scalars().all()
    assert len(rows) == 1
    assert rows[0].key_hash != body["plaintext_key"]
    assert rows[0].key_hash == hashlib.sha256(
        body["plaintext_key"].encode()
    ).hexdigest()


@pytest.mark.asyncio
async def test_create_api_key_writes_audit(client, admin_of_existing, db_session):
    r = await client.post(
        "/v1/auth/api-keys",
        json={"name": "Audited"},
        headers=_jwt_headers(admin_of_existing),
    )
    assert r.status_code == 201
    audits = (
        await db_session.execute(
            select(AuditLog).where(AuditLog.action == "auth.api_key.created")
        )
    ).scalars().all()
    assert len(audits) == 1
    assert audits[0].actor_id == admin_of_existing.id
    assert audits[0].details == {"api_key_prefix": r.json()["key_prefix"]}


@pytest.mark.asyncio
async def test_create_api_key_denies_non_admin(client, db_session):
    """A MEMBER-role user cannot mint keys."""
    org = Organization(name="Mem Co", slug=f"memco-{uuid4().hex[:6]}")
    db_session.add(org)
    await db_session.flush()
    await use_org(db_session, org.id)
    member = User(
        email="m@t.co", hashed_password=hash_password("MemberPass1!"),
        full_name="Mem", email_verified=True,
    )
    db_session.add(member)
    await db_session.flush()
    db_session.add(
        Membership(user_id=member.id, organization_id=org.id, role=MembershipRole.MEMBER)
    )
    await db_session.commit()

    r = await client.post(
        "/v1/auth/api-keys",
        json={"name": "nope"},
        headers=_jwt_headers(member),
    )
    assert r.status_code == 403
    assert r.json()["detail"] == "insufficient_role"


@pytest.mark.asyncio
async def test_create_api_key_rejects_api_key_auth(
    client, admin_of_existing, db_session
):
    """Mutation endpoints require JWT — an API key cannot mint another
    API key (prevents a leaked key from bootstrapping persistence)."""
    # First, create a key via JWT.
    create_r = await client.post(
        "/v1/auth/api-keys",
        json={"name": "bootstrap"},
        headers=_jwt_headers(admin_of_existing),
    )
    plaintext = create_r.json()["plaintext_key"]

    # Try to use THAT key to create another key.
    r = await client.post(
        "/v1/auth/api-keys",
        json={"name": "escalation_attempt"},
        headers={"Authorization": f"Bearer {plaintext}"},
    )
    assert r.status_code == 403
    assert r.json()["detail"] == "api_key_insufficient_for_operation"


@pytest.mark.asyncio
async def test_create_api_key_rate_limited_at_10_per_hour(
    client, admin_of_existing
):
    for i in range(10):
        r = await client.post(
            "/v1/auth/api-keys",
            json={"name": f"k{i}"},
            headers=_jwt_headers(admin_of_existing),
        )
        assert r.status_code == 201, f"{i}: {r.text}"
    r = await client.post(
        "/v1/auth/api-keys",
        json={"name": "overflow"},
        headers=_jwt_headers(admin_of_existing),
    )
    assert r.status_code == 429
    assert r.json()["detail"] == "rate_limit_exceeded"


# ---------------------------------------------------------------- list


@pytest.mark.asyncio
async def test_list_api_keys_returns_own_org_keys_no_plaintext(
    client, admin_of_existing, db_session
):
    # Create two keys.
    for name in ("first", "second"):
        await client.post(
            "/v1/auth/api-keys",
            json={"name": name},
            headers=_jwt_headers(admin_of_existing),
        )

    r = await client.get(
        "/v1/auth/api-keys",
        headers=_jwt_headers(admin_of_existing),
    )
    assert r.status_code == 200
    body = r.json()
    assert len(body) == 2
    for item in body:
        assert set(item.keys()) == {
            "id", "name", "key_prefix",
            "last_used_at", "revoked_at", "created_at",
        }
        assert "plaintext_key" not in item
        assert "key_hash" not in item


@pytest.mark.asyncio
async def test_list_api_keys_cross_tenant_isolation(client, db_session):
    """App-layer scoping (ADR-012): Org B admin cannot see Org A keys.

    This is the replacement for the DB-layer RLS test — the endpoint
    handler filters `WHERE organization_id = identity.organization_id`,
    which is the real defense.
    """
    org_a, admin_a = await _make_org_and_admin(db_session, slug_suffix="a")
    org_b, admin_b = await _make_org_and_admin(db_session, slug_suffix="b")

    # Org A admin creates a key.
    r = await client.post(
        "/v1/auth/api-keys",
        json={"name": "A-key"},
        headers=_jwt_headers(admin_a),
    )
    assert r.status_code == 201

    # Org B admin lists — must NOT see Org A's key.
    r = await client.get(
        "/v1/auth/api-keys",
        headers=_jwt_headers(admin_b),
    )
    assert r.status_code == 200
    assert r.json() == []


@pytest.mark.asyncio
async def test_list_api_keys_includes_revoked(
    client, admin_of_existing, db_session
):
    """Revoked keys still appear in list (with revoked_at populated) —
    useful for auditing. Filtering happens at authentication time,
    not at listing time."""
    create_r = await client.post(
        "/v1/auth/api-keys",
        json={"name": "will-revoke"},
        headers=_jwt_headers(admin_of_existing),
    )
    key_id = create_r.json()["id"]

    del_r = await client.delete(
        f"/v1/auth/api-keys/{key_id}",
        headers=_jwt_headers(admin_of_existing),
    )
    assert del_r.status_code == 204

    list_r = await client.get(
        "/v1/auth/api-keys",
        headers=_jwt_headers(admin_of_existing),
    )
    assert list_r.status_code == 200
    items = list_r.json()
    assert len(items) == 1
    assert items[0]["revoked_at"] is not None


@pytest.mark.asyncio
async def test_list_api_keys_accepts_api_key_auth(
    client, admin_of_existing, db_session
):
    """Per policy: list accepts either JWT or API-key credentials
    (CI inventory use case)."""
    create_r = await client.post(
        "/v1/auth/api-keys",
        json={"name": "self-inspect"},
        headers=_jwt_headers(admin_of_existing),
    )
    plaintext = create_r.json()["plaintext_key"]

    r = await client.get(
        "/v1/auth/api-keys",
        headers={"Authorization": f"Bearer {plaintext}"},
    )
    assert r.status_code == 200
    assert len(r.json()) == 1


# ---------------------------------------------------------------- delete


@pytest.mark.asyncio
async def test_revoke_api_key_happy_path(
    client, admin_of_existing, db_session
):
    create_r = await client.post(
        "/v1/auth/api-keys",
        json={"name": "to-delete"},
        headers=_jwt_headers(admin_of_existing),
    )
    key_id = create_r.json()["id"]

    r = await client.delete(
        f"/v1/auth/api-keys/{key_id}",
        headers=_jwt_headers(admin_of_existing),
    )
    assert r.status_code == 204

    # revoked_at is set in the DB.
    row = (
        await db_session.execute(select(APIKey).where(APIKey.id == key_id))
    ).scalar_one()
    assert row.revoked_at is not None


@pytest.mark.asyncio
async def test_revoke_api_key_audit(
    client, admin_of_existing, db_session
):
    create_r = await client.post(
        "/v1/auth/api-keys",
        json={"name": "audit-me"},
        headers=_jwt_headers(admin_of_existing),
    )
    key_id = create_r.json()["id"]
    prefix = create_r.json()["key_prefix"]

    await client.delete(
        f"/v1/auth/api-keys/{key_id}",
        headers=_jwt_headers(admin_of_existing),
    )
    audits = (
        await db_session.execute(
            select(AuditLog).where(AuditLog.action == "auth.api_key.revoked")
        )
    ).scalars().all()
    assert len(audits) == 1
    assert audits[0].details == {"api_key_prefix": prefix}


@pytest.mark.asyncio
async def test_revoke_cross_tenant_returns_404(client, db_session):
    """Org B admin cannot delete Org A's key — 404 (not 403/410) to
    avoid leaking the existence of keys in other orgs."""
    org_a, admin_a = await _make_org_and_admin(db_session, slug_suffix="a")
    org_b, admin_b = await _make_org_and_admin(db_session, slug_suffix="b")

    create_r = await client.post(
        "/v1/auth/api-keys",
        json={"name": "A-only"},
        headers=_jwt_headers(admin_a),
    )
    assert create_r.status_code == 201
    a_key_id = create_r.json()["id"]

    # Org B admin tries to delete Org A's key.
    r = await client.delete(
        f"/v1/auth/api-keys/{a_key_id}",
        headers=_jwt_headers(admin_b),
    )
    assert r.status_code == 404
    assert r.json()["detail"] == "api_key_not_found"


@pytest.mark.asyncio
async def test_revoke_already_revoked_returns_410(
    client, admin_of_existing, db_session
):
    create_r = await client.post(
        "/v1/auth/api-keys",
        json={"name": "double-delete"},
        headers=_jwt_headers(admin_of_existing),
    )
    key_id = create_r.json()["id"]

    r1 = await client.delete(
        f"/v1/auth/api-keys/{key_id}",
        headers=_jwt_headers(admin_of_existing),
    )
    assert r1.status_code == 204

    r2 = await client.delete(
        f"/v1/auth/api-keys/{key_id}",
        headers=_jwt_headers(admin_of_existing),
    )
    assert r2.status_code == 410
    assert r2.json()["detail"] == "api_key_already_revoked"


@pytest.mark.asyncio
async def test_revoke_denies_non_admin(client, db_session):
    org, admin = await _make_org_and_admin(db_session, slug_suffix="rev")
    create_r = await client.post(
        "/v1/auth/api-keys",
        json={"name": "admin-only-can-revoke"},
        headers=_jwt_headers(admin),
    )
    key_id = create_r.json()["id"]

    # Add a MEMBER to the same org.
    await use_org(db_session, org.id)
    member = User(
        email="m2@t.co", hashed_password=hash_password("MemberPass1!"),
        full_name="M", email_verified=True,
    )
    db_session.add(member)
    await db_session.flush()
    db_session.add(
        Membership(user_id=member.id, organization_id=org.id, role=MembershipRole.MEMBER)
    )
    await db_session.commit()

    r = await client.delete(
        f"/v1/auth/api-keys/{key_id}",
        headers=_jwt_headers(member),
    )
    assert r.status_code == 403
    assert r.json()["detail"] == "insufficient_role"


@pytest.mark.asyncio
async def test_revoke_rejects_api_key_auth(
    client, admin_of_existing, db_session
):
    """Mutation: API-key credential is rejected with 403."""
    create_r = await client.post(
        "/v1/auth/api-keys",
        json={"name": "target"},
        headers=_jwt_headers(admin_of_existing),
    )
    key_id = create_r.json()["id"]
    plaintext = create_r.json()["plaintext_key"]

    r = await client.delete(
        f"/v1/auth/api-keys/{key_id}",
        headers={"Authorization": f"Bearer {plaintext}"},
    )
    assert r.status_code == 403
    assert r.json()["detail"] == "api_key_insufficient_for_operation"


# ---------------------------------------------------------------- /auth/me with API key


@pytest.mark.asyncio
async def test_me_returns_identity_for_api_key(
    client, admin_of_existing, db_session
):
    """Task 2.4: /auth/me accepts API-key credentials. Response has
    kind=api_key, user null, api_key populated."""
    create_r = await client.post(
        "/v1/auth/api-keys",
        json={"name": "ci"},
        headers=_jwt_headers(admin_of_existing),
    )
    plaintext = create_r.json()["plaintext_key"]

    r = await client.get(
        "/v1/auth/me",
        headers={"Authorization": f"Bearer {plaintext}"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["kind"] == "api_key"
    assert body["user"] is None
    assert body["api_key"]["key_prefix"] == create_r.json()["key_prefix"]
    assert "organization" in body
    # The plaintext must NEVER appear in /auth/me responses.
    assert "plaintext_key" not in body["api_key"]
    assert plaintext not in r.text


# ---------------------------------------------------------------- schema distinctness


def test_created_response_and_summary_are_distinct_schemas():
    """Regression guard: the one-time create response and the
    list-item response are separate types. Preventing a future
    refactor from merging them (and leaking plaintext_key into a
    list response) is load-bearing security discipline.
    """
    created_fields = set(APIKeyCreatedResponse.model_fields.keys())
    summary_fields = set(APIKeySummary.model_fields.keys())
    assert "plaintext_key" in created_fields
    assert "plaintext_key" not in summary_fields
    assert APIKeyCreatedResponse is not APIKeySummary
    # Field sets must differ on at least plaintext_key + revoked_at.
    assert created_fields != summary_fields
