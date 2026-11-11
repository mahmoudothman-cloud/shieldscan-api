"""GET /plans, GET /orgs/{id}/billing/summary, and scan metering (M12 slice 1)."""

from __future__ import annotations

import pytest
from sqlalchemy import select

from app.models.billing import SubscriptionStatus
from app.models.identity import Membership
from app.services.plans import current_subscription
from tests.routes.test_scans import _url, project_setup  # noqa: F401 — fixture re-export


@pytest.mark.asyncio
async def test_plans_is_public_and_lists_live_public_versions(client):
    r = await client.get("/v1/plans")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["vat_included"] is True and body["vat_rate_percent"] == 14
    codes = [p["code"] for p in body["plans"]]
    assert codes == ["free", "starter", "growth", "business"]  # enterprise is not public
    starter = next(p for p in body["plans"] if p["code"] == "starter")
    intervals = {p["billing_interval"]: p for p in starter["prices"]}
    assert intervals["month"]["price_egp_cents"] == 99_900
    assert intervals["year"]["price_egp_cents"] == 999_000
    assert intervals["month"]["limits"]["scans.full.per_period"] == 10
    assert intervals["month"]["features"]["ai_fix"] is True
    free = next(p for p in body["plans"] if p["code"] == "free")
    assert [p["billing_interval"] for p in free["prices"]] == ["month"]


@pytest.mark.asyncio
async def test_registration_puts_the_org_on_free(db_session, existing_user):
    user, _ = existing_user
    org_id = (
        await db_session.execute(
            select(Membership.organization_id).where(Membership.user_id == user.id)
        )
    ).scalar_one()
    sub = await current_subscription(db_session, org_id)
    assert sub is not None and sub.status == SubscriptionStatus.ACTIVE
    assert sub.provider.value == "manual"


@pytest.mark.asyncio
async def test_billing_summary_requires_membership(client, project_setup, auth_headers):  # noqa: F811
    s = project_setup
    r = await client.get(f"/v1/orgs/{s['org'].id}/billing/summary", headers=auth_headers)
    assert r.status_code in (403, 404)


@pytest.mark.asyncio
async def test_billing_summary_reflects_metered_scans(client, project_setup):  # noqa: F811
    s = project_setup
    before = await client.get(f"/v1/orgs/{s['org'].id}/billing/summary", headers=s["headers"])
    assert before.status_code == 200, before.text
    b = before.json()
    assert b["plan_code"] == "free"  # no subscription row → Free
    assert b["usage"]["scans.full.per_period"] == 0
    assert b["limits"]["projects.max"] == 1

    r = await client.post(_url(s), json={"scan_type": "full_web"}, headers=s["headers"])
    assert r.status_code == 201, r.text
    r = await client.post(_url(s), json={"scan_type": "quick"}, headers=s["headers"])
    assert r.status_code == 201, r.text

    after = (
        await client.get(f"/v1/orgs/{s['org'].id}/billing/summary", headers=s["headers"])
    ).json()
    assert after["usage"]["scans.full.per_period"] == 1
    assert after["usage"]["scans.quick.per_period"] == 1
    assert after["period_start"] == b["period_start"]
