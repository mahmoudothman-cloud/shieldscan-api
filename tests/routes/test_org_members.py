"""Tests for org settings + membership management (M11 pre-work).

    GET/PATCH  /v1/orgs/{org_id}
    GET/POST   /v1/orgs/{org_id}/members
    PATCH/DEL  /v1/orgs/{org_id}/members/{user_id}

Scenarios:
  1. auth: 401 unauthenticated; 404 for a member of another org
  2. GET org carries member_count + caller's role
  3. PATCH org: admin updates fields → audit organization.updated with
     the changed field names; member → 403; no-op PATCH writes no audit
  4. members list ordered by join time
  5. invite existing user → membership, no new user, email sent;
     duplicate → 409 already_member
  6. invite new address → user created unverified, invite email carries
     both tokens; audit invited_new_user=True
  7. non-admin invite → 403; API key invite → 403 (jwt_only)
  8. role change → audit previous_role/role; demoting the only admin → 409
  9. remove member → 204 + audit; removing the only admin → 409;
     unknown user_id → 404
"""

from __future__ import annotations

from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import select

from app.models.audit import AuditLog
from app.models.identity import Membership, MembershipRole, User
from app.services.auth import create_access_token
from tests.routes.test_scan_reads import _mk_org


def _hdr(user) -> dict[str, str]:
    return {"Authorization": f"Bearer {create_access_token(sub=str(user.id))}"}


async def _add_member(db_session, org, tag: str, role: MembershipRole):
    user = User(
        email=f"{tag}-{uuid4().hex[:6]}@t.co",
        hashed_password="x",
        full_name=tag,
        email_verified=True,
    )
    db_session.add(user)
    await db_session.flush()
    db_session.add(Membership(user_id=user.id, organization_id=org.id, role=role))
    await db_session.flush()
    return user


@pytest_asyncio.fixture
async def team(client, db_session):
    org, admin = await _mk_org(db_session, "team")
    member = await _add_member(db_session, org, "mem", MembershipRole.MEMBER)
    viewer = await _add_member(db_session, org, "view", MembershipRole.VIEWER)
    other_org, other_admin = await _mk_org(db_session, "other")
    await db_session.commit()
    return {
        "org": org,
        "admin": admin,
        "member": member,
        "viewer": viewer,
        "other_org": other_org,
        "other_admin": other_admin,
    }


async def _audit_rows(db_session, action: str):
    return (
        (
            await db_session.execute(
                select(AuditLog).where(AuditLog.action == action).order_by(AuditLog.created_at)
            )
        )
        .scalars()
        .all()
    )


# ---------------------------------------------------------------- auth + GET


@pytest.mark.asyncio
async def test_org_get_auth(client, team):
    url = f"/v1/orgs/{team['org'].id}"
    assert (await client.get(url)).status_code == 401
    r = await client.get(url, headers=_hdr(team["other_admin"]))
    assert r.status_code == 404
    r = await client.get(f"{url}/members", headers=_hdr(team["other_admin"]))
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_org_get(client, team):
    r = await client.get(f"/v1/orgs/{team['org'].id}", headers=_hdr(team["viewer"]))
    assert r.status_code == 200
    body = r.json()
    assert body["slug"] == team["org"].slug
    assert body["member_count"] == 3
    assert body["my_role"] == "viewer"


# ---------------------------------------------------------------- PATCH org


@pytest.mark.asyncio
async def test_org_patch_admin_and_audit(client, db_session, team):
    url = f"/v1/orgs/{team['org'].id}"
    r = await client.patch(
        url,
        json={"name": "  Renamed Co ", "country": "eg", "industry": "fintech"},
        headers=_hdr(team["admin"]),
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["name"] == "Renamed Co"
    assert body["country"] == "EG"
    assert body["industry"] == "fintech"
    assert body["my_role"] == "admin"

    rows = await _audit_rows(db_session, "organization.updated")
    assert len(rows) == 1
    assert rows[0].details["fields"] == ["country", "industry", "name"]
    assert rows[0].actor_id == team["admin"].id

    # Same values again → no change, no second audit row.
    r = await client.patch(url, json={"name": "Renamed Co"}, headers=_hdr(team["admin"]))
    assert r.status_code == 200
    assert len(await _audit_rows(db_session, "organization.updated")) == 1


@pytest.mark.asyncio
async def test_org_patch_rejects_member_and_unknown_fields(client, team):
    url = f"/v1/orgs/{team['org'].id}"
    r = await client.patch(url, json={"name": "Nope"}, headers=_hdr(team["member"]))
    assert r.status_code == 403
    assert r.json()["detail"] == "insufficient_role"
    r = await client.patch(url, json={"slug": "hijack"}, headers=_hdr(team["admin"]))
    assert r.status_code == 422


# ---------------------------------------------------------------- members list


@pytest.mark.asyncio
async def test_members_list(client, team):
    r = await client.get(f"/v1/orgs/{team['org'].id}/members", headers=_hdr(team["member"]))
    assert r.status_code == 200
    rows = r.json()
    assert [m["role"] for m in rows] == ["admin", "member", "viewer"]
    assert rows[0]["user_id"] == str(team["admin"].id)
    assert {"user_id", "email", "full_name", "role", "email_verified", "joined_at"} <= set(rows[0])


# ---------------------------------------------------------------- invite


@pytest.mark.asyncio
async def test_invite_existing_user(client, db_session, team, email_service_stub):
    url = f"/v1/orgs/{team['org'].id}/members"
    target = team["other_admin"]  # exists, belongs to another org
    r = await client.post(
        url, json={"email": target.email.upper(), "role": "member"}, headers=_hdr(team["admin"])
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["user_id"] == str(target.id)
    assert body["role"] == "member"
    assert body["invited_new_user"] is False

    users = (
        (await db_session.execute(select(User).where(User.email == target.email))).scalars().all()
    )
    assert len(users) == 1

    assert len(email_service_stub.outbox) == 1
    assert email_service_stub.outbox[0].to == target.email
    assert "accept-invite" not in email_service_stub.outbox[0].body

    rows = await _audit_rows(db_session, "organization.member_invited")
    assert len(rows) == 1
    assert rows[0].details == {
        "target_user_id": str(target.id),
        "role": "member",
        "invited_new_user": False,
    }

    # Second invite of the same address → 409.
    r = await client.post(url, json={"email": target.email}, headers=_hdr(team["admin"]))
    assert r.status_code == 409
    assert r.json()["detail"] == "already_member"


@pytest.mark.asyncio
async def test_invite_new_user(client, db_session, team, email_service_stub, fake_redis):
    url = f"/v1/orgs/{team['org'].id}/members"
    r = await client.post(
        url,
        json={"email": "New.Person@Example.com", "role": "viewer", "full_name": "New Person"},
        headers=_hdr(team["admin"]),
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["email"] == "new.person@example.com"
    assert body["full_name"] == "New Person"
    assert body["role"] == "viewer"
    assert body["email_verified"] is False
    assert body["invited_new_user"] is True

    user = (
        await db_session.execute(select(User).where(User.email == "new.person@example.com"))
    ).scalar_one()
    assert user.email_verified is False

    assert len(email_service_stub.outbox) == 1
    mail = email_service_stub.outbox[0]
    assert mail.to == "new.person@example.com"
    assert "accept-invite?reset=" in mail.body and "&verify=" in mail.body
    assert team["org"].name in mail.subject

    # Both tokens were minted in Redis (hashed keys; just count the namespaces).
    keys = await fake_redis.keys("*")
    assert any(k.startswith("password_reset:") for k in keys)
    assert any(k.startswith("email_verify:") for k in keys)

    rows = await _audit_rows(db_session, "organization.member_invited")
    assert rows[0].details["invited_new_user"] is True
    assert rows[0].details["target_user_id"] == str(user.id)


@pytest.mark.asyncio
async def test_invite_requires_admin_jwt(client, db_session, team):
    url = f"/v1/orgs/{team['org'].id}/members"
    r = await client.post(url, json={"email": "x@t.co"}, headers=_hdr(team["member"]))
    assert r.status_code == 403

    # API key (admin-equivalent elsewhere) is refused: human-in-the-loop only.
    import hashlib

    from app.models.identity import APIKey

    plaintext = f"ss_live_test_{uuid4().hex[:24]}"
    db_session.add(
        APIKey(
            organization_id=team["org"].id,
            name="ci",
            key_prefix=plaintext[:12],
            key_hash=hashlib.sha256(plaintext.encode()).hexdigest(),
        )
    )
    await db_session.commit()
    r = await client.post(
        url, json={"email": "x@t.co"}, headers={"Authorization": f"Bearer {plaintext}"}
    )
    assert r.status_code == 403
    assert r.json()["detail"] == "api_key_insufficient_for_operation"


# ---------------------------------------------------------------- role change


@pytest.mark.asyncio
async def test_change_role_and_last_admin_guard(client, db_session, team):
    base = f"/v1/orgs/{team['org'].id}/members"
    # Promote member → admin.
    r = await client.patch(
        f"{base}/{team['member'].id}", json={"role": "admin"}, headers=_hdr(team["admin"])
    )
    assert r.status_code == 200, r.text
    assert r.json()["role"] == "admin"
    rows = await _audit_rows(db_session, "organization.member_role_changed")
    assert len(rows) == 1
    assert rows[0].details["previous_role"] == "member"
    assert rows[0].details["role"] == "admin"

    # Two admins now: demoting the original admin is allowed.
    r = await client.patch(
        f"{base}/{team['admin'].id}", json={"role": "member"}, headers=_hdr(team["member"])
    )
    assert r.status_code == 200

    # Only one admin left (member): demoting them → 409.
    r = await client.patch(
        f"{base}/{team['member'].id}", json={"role": "viewer"}, headers=_hdr(team["member"])
    )
    assert r.status_code == 409
    assert r.json()["detail"] == "last_admin"

    # Same role → no-op 200, no extra audit row.
    r = await client.patch(
        f"{base}/{team['member'].id}", json={"role": "admin"}, headers=_hdr(team["member"])
    )
    assert r.status_code == 200
    assert len(await _audit_rows(db_session, "organization.member_role_changed")) == 2

    # Demoted original admin can no longer manage members.
    r = await client.patch(
        f"{base}/{team['viewer'].id}", json={"role": "member"}, headers=_hdr(team["admin"])
    )
    assert r.status_code == 403


# ---------------------------------------------------------------- remove


@pytest.mark.asyncio
async def test_remove_member(client, db_session, team):
    base = f"/v1/orgs/{team['org'].id}/members"
    r = await client.delete(f"{base}/{team['viewer'].id}", headers=_hdr(team["admin"]))
    assert r.status_code == 204
    left = (
        (
            await db_session.execute(
                select(Membership).where(Membership.organization_id == team["org"].id)
            )
        )
        .scalars()
        .all()
    )
    assert {m.user_id for m in left} == {team["admin"].id, team["member"].id}
    # Account survives (may belong to other orgs).
    assert await db_session.get(User, team["viewer"].id) is not None

    rows = await _audit_rows(db_session, "organization.member_removed")
    assert len(rows) == 1
    assert rows[0].details == {
        "target_user_id": str(team["viewer"].id),
        "previous_role": "viewer",
    }

    # Only admin cannot remove themselves.
    r = await client.delete(f"{base}/{team['admin'].id}", headers=_hdr(team["admin"]))
    assert r.status_code == 409
    assert r.json()["detail"] == "last_admin"

    # Unknown user → 404; non-admin → 403.
    r = await client.delete(f"{base}/{uuid4()}", headers=_hdr(team["admin"]))
    assert r.status_code == 404
    r = await client.delete(f"{base}/{team['admin'].id}", headers=_hdr(team["member"]))
    assert r.status_code == 403
