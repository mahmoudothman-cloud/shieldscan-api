"""Platform-admin routes (M12 slice 3)."""

from __future__ import annotations

from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import select

from app.config import settings
from app.models.audit import AuditLog
from app.models.identity import Membership, MembershipRole, Organization, User
from app.services.auth import create_access_token, hash_password
from app.services.plans import LIMIT_KEYS, live_version
from tests.conftest import use_org


async def _mk_user(db_session, org_id, *, platform_admin: bool) -> User:
    user = User(
        email=f"a-{uuid4().hex[:6]}@t.co",
        hashed_password=hash_password("AdminPass-1"),
        full_name="A",
        email_verified=True,
        is_platform_admin=platform_admin,
    )
    db_session.add(user)
    await db_session.flush()
    db_session.add(Membership(user_id=user.id, organization_id=org_id, role=MembershipRole.ADMIN))
    await db_session.flush()
    return user


@pytest_asyncio.fixture
async def setup(client, db_session):
    org = Organization(name="Ops Org", slug=f"ops-{uuid4().hex[:8]}")
    db_session.add(org)
    await db_session.flush()
    await use_org(db_session, org.id)
    admin = await _mk_user(db_session, org.id, platform_admin=True)
    plain = await _mk_user(db_session, org.id, platform_admin=False)
    # A second org to operate on.
    target = Organization(name="Customer Org", slug=f"cust-{uuid4().hex[:8]}")
    db_session.add(target)
    await db_session.flush()
    await use_org(db_session, target.id)
    customer = await _mk_user(db_session, target.id, platform_admin=False)
    await db_session.commit()
    return {
        "org": org,
        "target": target,
        "customer": customer,
        "admin_headers": {"Authorization": f"Bearer {create_access_token(sub=str(admin.id))}"},
        "plain_headers": {"Authorization": f"Bearer {create_access_token(sub=str(plain.id))}"},
        "customer_headers": {
            "Authorization": f"Bearer {create_access_token(sub=str(customer.id))}"
        },
    }


def _starter_body(**changes):
    limits = {k: 5 for k in LIMIT_KEYS}
    body = {
        "billing_interval": "month",
        "price_egp_cents": 119_900,
        "price_usd_cents": 3_400,
        "limits": limits,
        "features": {
            "ai_fix": True,
            "cross_layer": False,
            "compliance.frameworks": [],
            "cli_write": True,
            "priority_queue": False,
            "sso": False,
        },
        "change_note": "price rise",
    }
    body.update(changes)
    return body


@pytest.mark.asyncio
async def test_admin_routes_need_the_flag(client, setup):
    r = await client.get("/v1/admin/plans", headers=setup["plain_headers"])
    assert r.status_code == 403
    r = await client.get("/v1/admin/plans")
    assert r.status_code == 401
    r = await client.get("/v1/admin/plans", headers=setup["admin_headers"])
    assert r.status_code == 200, r.text
    assert [p["code"] for p in r.json()["plans"]] == [
        "free",
        "starter",
        "growth",
        "business",
        "enterprise",
    ]
    assert r.json()["limit_keys"] == list(LIMIT_KEYS)


@pytest.mark.asyncio
async def test_me_exposes_platform_admin(client, setup):
    r = await client.get("/v1/auth/me", headers=setup["admin_headers"])
    assert r.status_code == 200, r.text
    assert r.json()["user"]["is_platform_admin"] is True
    r = await client.get("/v1/auth/me", headers=setup["plain_headers"])
    assert r.json()["user"]["is_platform_admin"] is False


@pytest.mark.asyncio
async def test_publish_version_retires_old_and_grandfathers(client, setup, db_session):
    h = setup["admin_headers"]
    old = await live_version(db_session, "starter")
    assert old is not None
    # The customer org is put on Starter v1 first.
    r = await client.post(
        f"/v1/admin/orgs/{setup['target'].id}/subscription",
        json={"plan_code": "starter", "note": "design partner"},
        headers=h,
    )
    assert r.status_code == 201, r.text
    assert r.json()["plan_version_id"] == str(old.id)

    r = await client.post("/v1/admin/plans/starter/versions", json=_starter_body(), headers=h)
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["version"]["version"] == 2
    assert body["retired"]["id"] == str(old.id)
    fields = {d["field"]: (d["before"], d["after"]) for d in body["diff"]}
    assert fields["price_egp_cents"] == (99_900, 119_900)
    assert fields["limits.users.max"] == (3, 5)

    # Public catalog shows the new price; the subscriber keeps v1.
    r = await client.get("/v1/plans")
    starter = next(p for p in r.json()["plans"] if p["code"] == "starter")
    month = next(x for x in starter["prices"] if x["billing_interval"] == "month")
    assert month["price_egp_cents"] == 119_900
    r = await client.get(f"/v1/admin/orgs/{setup['target'].id}", headers=h)
    assert r.json()["subscription"]["plan_version_id"] == str(old.id)
    assert r.json()["effective_limits"]["users.max"] == 3

    # Bad bodies are refused.
    r = await client.post(
        "/v1/admin/plans/starter/versions",
        json=_starter_body(limits={"projects.max": 1}),
        headers=h,
    )
    assert r.status_code == 422
    r = await client.post(
        "/v1/admin/plans/starter/versions",
        json=_starter_body(features={**_starter_body()["features"], "ai_fix": "yes"}),
        headers=h,
    )
    assert r.status_code == 422
    r = await client.get("/v1/admin/plans/starter/versions", headers=h)
    assert [v["version"] for v in r.json() if v["billing_interval"] == "month"] == [2, 1]


@pytest.mark.asyncio
async def test_overrides_round_trip_with_audit(client, setup, db_session, fake_redis):
    h = setup["admin_headers"]
    target = setup["target"]
    settings.PLAN_LIMITS_ENFORCED = True
    # Customer on Free: one project max.
    r = await client.get(f"/v1/orgs/{target.id}/billing/summary", headers=setup["customer_headers"])
    assert r.json()["limits"]["projects.max"] == 1

    r = await client.put(
        f"/v1/admin/orgs/{target.id}/overrides/projects.max",
        json={"value": 10, "reason": "pilot"},
        headers=h,
    )
    assert r.status_code == 200, r.text
    assert r.json()["value"] == 10 and r.json()["reason"] == "pilot"
    r = await client.put(
        f"/v1/admin/orgs/{target.id}/overrides/ai_fix", json={"value": True}, headers=h
    )
    assert r.status_code == 200, r.text
    r = await client.put(
        f"/v1/admin/orgs/{target.id}/overrides/ai_fix", json={"value": "yes"}, headers=h
    )
    assert r.status_code == 422
    r = await client.put(f"/v1/admin/orgs/{target.id}/overrides/nope", json={"value": 1}, headers=h)
    assert r.status_code == 422

    # The cache was invalidated: the customer sees it at once.
    r = await client.get(f"/v1/orgs/{target.id}/billing/summary", headers=setup["customer_headers"])
    assert r.json()["limits"]["projects.max"] == 10
    assert r.json()["features"]["ai_fix"] is True
    assert sorted(r.json()["overrides"]) == ["ai_fix", "projects.max"]

    r = await client.delete(f"/v1/admin/orgs/{target.id}/overrides/ai_fix", headers=h)
    assert r.status_code == 204
    r = await client.delete(f"/v1/admin/orgs/{target.id}/overrides/ai_fix", headers=h)
    assert r.status_code == 404
    r = await client.get(f"/v1/admin/orgs/{target.id}", headers=h)
    assert [o["key"] for o in r.json()["overrides"]] == ["projects.max"]

    # Audit rows landed in the TARGET org's log.
    await use_org(db_session, target.id)
    actions = list(
        (
            await db_session.execute(
                select(AuditLog.action)
                .where(AuditLog.organization_id == target.id, AuditLog.action.like("admin.%"))
                .order_by(AuditLog.created_at)
            )
        ).scalars()
    )
    assert actions == ["admin.override_set", "admin.override_set", "admin.override_removed"]


@pytest.mark.asyncio
async def test_list_orgs_and_plan_patch(client, setup):
    h = setup["admin_headers"]
    r = await client.get("/v1/admin/orgs", params={"q": "customer"}, headers=h)
    assert r.status_code == 200, r.text
    assert r.json()["total"] == 1
    org = r.json()["orgs"][0]
    assert (
        org["slug"] == setup["target"].slug and org["plan_code"] == "free" and org["members"] == 1
    )

    r = await client.patch(
        "/v1/admin/plans/enterprise", json={"is_public": True, "rank": 99}, headers=h
    )
    assert r.status_code == 200, r.text
    assert r.json()["is_public"] is True
    r = await client.patch("/v1/admin/plans/free", json={"archived": True}, headers=h)
    assert r.status_code == 409
    r = await client.post(
        "/v1/admin/plans",
        json={"code": "partner", "name": "Partner", "is_public": False},
        headers=h,
    )
    assert r.status_code == 201, r.text
    assert r.json()["live_versions"] == []
    r = await client.post("/v1/admin/plans", json={"code": "partner", "name": "Dup"}, headers=h)
    assert r.status_code == 409
    r = await client.post("/v1/admin/plans/partner/versions", json=_starter_body(), headers=h)
    assert r.status_code == 201, r.text
    assert r.json()["retired"] is None and r.json()["version"]["version"] == 1
