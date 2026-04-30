"""End-to-end tests for /v1/orgs/{org_id}/projects/{id}/credentials (Task 3.X).

17 tests pinning the credential-CRUD contract:

  Happy paths (one per auth_type):
   1. basic
   2. bearer
   3. cookie
   4. custom_header
   5. form

  Replace + clear semantics:
   6. PATCH replaces existing in place (basic → bearer, single row, audit)
   7. DELETE clears credential (204 + PROJECT_CREDENTIAL_DELETED audit)

  Validation:
   8. Invalid auth_type → 422
   9. Missing required field per type → 422

  Auth + tenant:
  10. Cross-tenant project → 404
  11. JWT non-admin member → 403
  12. API key (any role context) → 200

  Security regressions:
  13. PATCH response never returns decrypted credential
  14. encrypted_data column is actually encrypted (byte-level + round-trip)

  Archive semantics:
  15. PATCH on archived project → 409
  16. DELETE on archived project → 409

  Infra:
  17. settings.FERNET_KEY is a valid Fernet key (early-fail discoverability)
"""

from __future__ import annotations

import json
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from cryptography.fernet import Fernet
from sqlalchemy import select

from app.config import settings
from app.models.audit import AuditLog
from app.models.identity import APIKey, Membership, MembershipRole, Organization, User
from app.models.projects import Project, ProjectCredential
from app.services.api_keys import generate_api_key
from app.services.auth import create_access_token, hash_password
from tests.conftest import use_org


# ---------------------------------------------------------------- 17. Fernet validity (collection-time)


def test_fernet_key_in_settings_is_valid_at_import():
    """Fail at collection time if FERNET_KEY is malformed.

    Fernet rejects keys that aren't 32 bytes of base64-urlsafe data.
    A broken FERNET_KEY would otherwise fail mid-test with a confusing
    InvalidToken / ValueError surface."""
    Fernet(settings.FERNET_KEY.encode())


# ---------------------------------------------------------------- fixtures


@pytest_asyncio.fixture
async def project_setup(client, db_session):
    """Org A admin + member + project + API key.
    Returns dict with all the headers + ids tests need."""
    org = Organization(name="Cred Org", slug=f"cred-{uuid4().hex[:8]}")
    db_session.add(org)
    await db_session.flush()
    await use_org(db_session, org.id)

    admin = User(
        email=f"adm-{uuid4().hex[:6]}@t.co",
        hashed_password=hash_password("AdmPass-1"),
        full_name="Admin",
        email_verified=True,
    )
    member = User(
        email=f"mbr-{uuid4().hex[:6]}@t.co",
        hashed_password=hash_password("MbrPass-1"),
        full_name="Mbr",
        email_verified=True,
    )
    db_session.add_all([admin, member])
    await db_session.flush()
    db_session.add_all([
        Membership(user_id=admin.id, organization_id=org.id, role=MembershipRole.ADMIN),
        Membership(user_id=member.id, organization_id=org.id, role=MembershipRole.MEMBER),
    ])

    project = Project(
        organization_id=org.id,
        name="C-app",
        target_url="https://example.com",
        root_domain="example.com",
    )
    db_session.add(project)

    plain, key_hash, prefix = generate_api_key("live")
    api_key = APIKey(
        organization_id=org.id,
        name="ci",
        key_prefix=prefix,
        key_hash=key_hash,
    )
    db_session.add(api_key)

    await db_session.commit()
    await db_session.refresh(project)

    return {
        "org": org,
        "project": project,
        "admin": admin,
        "member": member,
        "api_key": api_key,
        "admin_headers": {"Authorization": f"Bearer {create_access_token(sub=str(admin.id))}"},
        "member_headers": {"Authorization": f"Bearer {create_access_token(sub=str(member.id))}"},
        "api_key_headers": {"Authorization": f"Bearer {plain}"},
    }


@pytest_asyncio.fixture
async def other_org(db_session):
    """Second org with admin — used for cross-tenant tests."""
    org = Organization(name="Other Cred", slug=f"oc-{uuid4().hex[:8]}")
    db_session.add(org)
    await db_session.flush()
    await use_org(db_session, org.id)
    user = User(
        email=f"oc-{uuid4().hex[:6]}@t.co",
        hashed_password=hash_password("OcPass-1"),
        full_name="OC",
        email_verified=True,
    )
    db_session.add(user)
    await db_session.flush()
    db_session.add(
        Membership(user_id=user.id, organization_id=org.id, role=MembershipRole.ADMIN)
    )
    await db_session.commit()
    return {
        "org": org,
        "user": user,
        "headers": {"Authorization": f"Bearer {create_access_token(sub=str(user.id))}"},
    }


def _url(s):
    return f"/v1/orgs/{s['org'].id}/projects/{s['project'].id}/credentials"


# ---------------------------------------------------------------- 1-5. happy paths


@pytest.mark.asyncio
async def test_patch_basic_happy_path(project_setup, client, db_session):
    s = project_setup
    body = {"auth_type": "basic", "username": "alice", "password": "s3cret"}
    r = await client.patch(_url(s), json=body, headers=s["admin_headers"])
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["auth_type"] == "basic"
    assert out["configured"] is True
    # NEVER returns the secret values.
    assert "username" not in out
    assert "password" not in out

    # DB row created with auth_type set + encrypted_data populated.
    rows = (
        await db_session.execute(select(ProjectCredential))
    ).scalars().all()
    assert len(rows) == 1
    assert rows[0].auth_type == "basic"
    assert rows[0].encrypted_data  # non-empty bytes

    # Audit row.
    audits = (
        await db_session.execute(
            select(AuditLog).where(AuditLog.action == "project.credential.set")
        )
    ).scalars().all()
    assert len(audits) == 1
    assert audits[0].details == {"auth_type": "basic"}
    assert audits[0].actor_id == s["admin"].id


@pytest.mark.asyncio
async def test_patch_bearer_happy_path(project_setup, client):
    s = project_setup
    r = await client.patch(
        _url(s),
        json={"auth_type": "bearer", "token": "tok-xyz-123"},
        headers=s["admin_headers"],
    )
    assert r.status_code == 200, r.text
    assert r.json()["auth_type"] == "bearer"


@pytest.mark.asyncio
async def test_patch_cookie_happy_path(project_setup, client):
    s = project_setup
    r = await client.patch(
        _url(s),
        json={"auth_type": "cookie", "cookie_name": "sid", "cookie_value": "abc=="},
        headers=s["admin_headers"],
    )
    assert r.status_code == 200, r.text
    assert r.json()["auth_type"] == "cookie"


@pytest.mark.asyncio
async def test_patch_custom_header_happy_path(project_setup, client):
    s = project_setup
    r = await client.patch(
        _url(s),
        json={
            "auth_type": "custom_header",
            "header_name": "X-API-Key",
            "header_value": "xkey-1",
        },
        headers=s["admin_headers"],
    )
    assert r.status_code == 200, r.text
    assert r.json()["auth_type"] == "custom_header"


@pytest.mark.asyncio
async def test_patch_form_happy_path(project_setup, client):
    s = project_setup
    r = await client.patch(
        _url(s),
        json={
            "auth_type": "form",
            "login_url": "https://example.com/login",
            "username_field": "email",
            "password_field": "pw",
            "username": "alice@example.com",
            "password": "s3cret",
        },
        headers=s["admin_headers"],
    )
    assert r.status_code == 200, r.text
    assert r.json()["auth_type"] == "form"


# ---------------------------------------------------------------- 6. replace in place


@pytest.mark.asyncio
async def test_patch_replaces_existing_credential(project_setup, client, db_session):
    """basic → bearer replaces in-place: same project_id, single row,
    auth_type updated, fresh encrypted_data, two audit rows."""
    s = project_setup
    r1 = await client.patch(
        _url(s),
        json={"auth_type": "basic", "username": "u", "password": "p1"},
        headers=s["admin_headers"],
    )
    assert r1.status_code == 200

    rows1 = (await db_session.execute(select(ProjectCredential))).scalars().all()
    assert len(rows1) == 1
    original_id = rows1[0].id
    original_blob = rows1[0].encrypted_data

    r2 = await client.patch(
        _url(s),
        json={"auth_type": "bearer", "token": "new-tok"},
        headers=s["admin_headers"],
    )
    assert r2.status_code == 200
    assert r2.json()["auth_type"] == "bearer"

    rows2 = (await db_session.execute(select(ProjectCredential))).scalars().all()
    assert len(rows2) == 1, "PATCH must replace in-place — not append"
    # UPSERT semantics: same project_id row preserved (id may stay or
    # be regenerated; at minimum row count = 1).
    assert rows2[0].auth_type == "bearer"
    assert rows2[0].encrypted_data != original_blob

    # Two PROJECT_CREDENTIAL_SET audits (one per PATCH).
    audits = (
        await db_session.execute(
            select(AuditLog).where(AuditLog.action == "project.credential.set")
        )
    ).scalars().all()
    assert len(audits) == 2


# ---------------------------------------------------------------- 7. DELETE clears


@pytest.mark.asyncio
async def test_delete_credentials_204_and_audit(project_setup, client, db_session):
    s = project_setup
    # Set first.
    r0 = await client.patch(
        _url(s),
        json={"auth_type": "basic", "username": "u", "password": "p"},
        headers=s["admin_headers"],
    )
    assert r0.status_code == 200

    # Then delete.
    r = await client.delete(_url(s), headers=s["admin_headers"])
    assert r.status_code == 204
    assert r.content == b""

    rows = (await db_session.execute(select(ProjectCredential))).scalars().all()
    assert rows == []

    audits = (
        await db_session.execute(
            select(AuditLog).where(AuditLog.action == "project.credential.deleted")
        )
    ).scalars().all()
    assert len(audits) == 1
    assert audits[0].actor_id == s["admin"].id


# ---------------------------------------------------------------- 8. invalid auth_type


@pytest.mark.asyncio
async def test_patch_invalid_auth_type_422(project_setup, client):
    s = project_setup
    r = await client.patch(
        _url(s),
        json={"auth_type": "totally_made_up", "secret": "x"},
        headers=s["admin_headers"],
    )
    assert r.status_code == 422


# ---------------------------------------------------------------- 9. missing required field


@pytest.mark.asyncio
async def test_patch_missing_required_field_422(project_setup, client):
    """basic credential without password is a 422 (Pydantic discriminator)."""
    s = project_setup
    r = await client.patch(
        _url(s),
        json={"auth_type": "basic", "username": "alice"},
        headers=s["admin_headers"],
    )
    assert r.status_code == 422


# ---------------------------------------------------------------- 10. cross-tenant 404


@pytest.mark.asyncio
async def test_patch_cross_tenant_returns_404(project_setup, other_org, client):
    s = project_setup
    o = other_org
    # Other-org admin pointing at s's project — 404, not 403 (no leak).
    r = await client.patch(
        _url(s),
        json={"auth_type": "basic", "username": "u", "password": "p"},
        headers=o["headers"],
    )
    assert r.status_code == 404


# ---------------------------------------------------------------- 11. JWT non-admin 403


@pytest.mark.asyncio
async def test_patch_jwt_member_returns_403(project_setup, client):
    s = project_setup
    r = await client.patch(
        _url(s),
        json={"auth_type": "basic", "username": "u", "password": "p"},
        headers=s["member_headers"],
    )
    assert r.status_code == 403
    assert r.json()["detail"] == "insufficient_role"


# ---------------------------------------------------------------- 12. API key bypasses role


@pytest.mark.asyncio
async def test_patch_api_key_succeeds_regardless_of_role(project_setup, client, db_session):
    """API keys are admin-equivalent at creation time — no role check
    runs on API-key paths. CI/CD must be able to rotate creds."""
    s = project_setup
    r = await client.patch(
        _url(s),
        json={"auth_type": "basic", "username": "u", "password": "p"},
        headers=s["api_key_headers"],
    )
    assert r.status_code == 200, r.text

    audits = (
        await db_session.execute(
            select(AuditLog).where(AuditLog.action == "project.credential.set")
        )
    ).scalars().all()
    assert len(audits) == 1
    assert audits[0].actor_id is None  # API-key path: no user actor
    assert audits[0].details == {"auth_type": "basic"}


# ---------------------------------------------------------------- 13. response never returns decrypted


@pytest.mark.asyncio
async def test_patch_response_never_returns_decrypted_credential(project_setup, client):
    """Regression guard. Response shape must not surface ANY of the
    secret fields (username, password, token, cookie_value, etc.)."""
    s = project_setup
    body = {
        "auth_type": "form",
        "login_url": "https://example.com/login",
        "username_field": "email",
        "password_field": "pw",
        "username": "alice@example.com",
        "password": "supersecret-CANARY-VALUE",
    }
    r = await client.patch(_url(s), json=body, headers=s["admin_headers"])
    assert r.status_code == 200
    raw = r.text
    # Belt + suspenders: serialized response must not contain any
    # secret field name OR value.
    for forbidden in (
        "supersecret-CANARY-VALUE",
        "alice@example.com",
        "username_field",
        "password_field",
        "username",
        "password",
        "login_url",
        "token",
        "cookie_value",
        "header_value",
    ):
        assert forbidden not in raw, f"response leaked field/value: {forbidden}"


# ---------------------------------------------------------------- 14. db row is actually encrypted


@pytest.mark.asyncio
async def test_encrypted_data_in_db_is_actually_encrypted(project_setup, client, db_session):
    """Two-stage check:
      (a) byte-level: plaintext password NOT present in encrypted_data
      (b) round-trip: Fernet(FERNET_KEY).decrypt() yields the original payload"""
    s = project_setup
    canary = "CANARY-PLAINTEXT-MUST-NOT-LEAK"
    r = await client.patch(
        _url(s),
        json={"auth_type": "basic", "username": "alice", "password": canary},
        headers=s["admin_headers"],
    )
    assert r.status_code == 200

    row = (await db_session.execute(select(ProjectCredential))).scalar_one()
    assert isinstance(row.encrypted_data, (bytes, memoryview))
    blob = bytes(row.encrypted_data)
    # (a) plaintext absence
    assert canary.encode() not in blob, "plaintext leaked into encrypted_data"
    assert b"alice" not in blob

    # (b) round-trip via the encryption service
    from app.services.credentials import decrypt_credential
    decrypted = decrypt_credential(blob)
    assert decrypted == {"username": "alice", "password": canary}


# ---------------------------------------------------------------- 15. PATCH on archived → 409


@pytest.mark.asyncio
async def test_patch_archived_project_returns_409(project_setup, client, db_session):
    s = project_setup
    # Archive the project.
    s["project"].archived_at = __import__("datetime").datetime.now(
        __import__("datetime").timezone.utc
    )
    await db_session.commit()
    r = await client.patch(
        _url(s),
        json={"auth_type": "basic", "username": "u", "password": "p"},
        headers=s["admin_headers"],
    )
    assert r.status_code == 409
    assert r.json()["detail"] == "project_archived"


# ---------------------------------------------------------------- 16. DELETE on archived → 409


@pytest.mark.asyncio
async def test_delete_archived_project_returns_409(project_setup, client, db_session):
    s = project_setup
    # Set credential first (so DELETE has something), then archive.
    r0 = await client.patch(
        _url(s),
        json={"auth_type": "basic", "username": "u", "password": "p"},
        headers=s["admin_headers"],
    )
    assert r0.status_code == 200
    s["project"].archived_at = __import__("datetime").datetime.now(
        __import__("datetime").timezone.utc
    )
    await db_session.commit()
    r = await client.delete(_url(s), headers=s["admin_headers"])
    assert r.status_code == 409
    assert r.json()["detail"] == "project_archived"
