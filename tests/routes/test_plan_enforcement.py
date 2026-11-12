"""Plan-limit enforcement (M12 slice 2).

``project_setup`` builds an org with no subscription row, which resolves
to the live Free version: 1 user, 1 project, 1 API key, 5 quick + 1 full
scan per period, 0 mobile, 10 recon subdomains, no ai_fix / cross_layer /
cli_write, no compliance frameworks. That makes every cap reachable in
one or two requests.
"""

from __future__ import annotations

import hashlib
from uuid import uuid4

import pytest

from app.config import settings
from app.models.billing import OrgLimitOverride
from app.models.identity import APIKey
from app.services.plans import invalidate_limits
from tests.routes.test_scans import _url, project_setup  # noqa: F401 — fixture re-export


def _assert_402(r, key: str):
    assert r.status_code == 402, r.text
    d = r.json()["detail"]
    assert d["error"] == "plan_limit_reached"
    assert d["key"] == key
    assert d["plan"] == "free"
    assert d["upgrade_url"].endswith("/settings/billing")
    return d


@pytest.mark.asyncio
async def test_second_project_hits_projects_max(client, project_setup):  # noqa: F811
    settings.PLAN_LIMITS_ENFORCED = True
    s = project_setup
    r = await client.post(
        f"/v1/orgs/{s['org'].id}/projects",
        json={"name": "Second", "target_url": "https://two.example.com"},
        headers=s["headers"],
    )
    d = _assert_402(r, "projects.max")
    assert d["limit"] == 1 and d["current"] == 1


@pytest.mark.asyncio
async def test_override_lifts_the_cap(client, project_setup, db_session, fake_redis):  # noqa: F811
    settings.PLAN_LIMITS_ENFORCED = True
    s = project_setup
    db_session.add(
        OrgLimitOverride(organization_id=s["org"].id, key="projects.max", value=3, reason="partner")
    )
    await db_session.commit()
    await invalidate_limits(fake_redis, s["org"].id)
    r = await client.post(
        f"/v1/orgs/{s['org'].id}/projects",
        json={"name": "Second", "target_url": "https://two.example.com"},
        headers=s["headers"],
    )
    assert r.status_code == 201, r.text


@pytest.mark.asyncio
async def test_full_scan_meter_and_mobile_zero(client, project_setup):  # noqa: F811
    settings.PLAN_LIMITS_ENFORCED = True
    s = project_setup
    r = await client.post(_url(s), json={"scan_type": "full_web"}, headers=s["headers"])
    assert r.status_code == 201, r.text
    r = await client.post(_url(s), json={"scan_type": "api"}, headers=s["headers"])  # same meter
    d = _assert_402(r, "scans.full.per_period")
    assert d["limit"] == 1 and d["current"] == 1
    # Quick scans have their own meter and still work.
    r = await client.post(_url(s), json={"scan_type": "quick"}, headers=s["headers"])
    assert r.status_code == 201, r.text
    # Mobile is 0 on Free.
    r = await client.post(
        _url(s),
        json={"scan_type": "mobile", "mobile_upload_id": str(s["upload"].id)},
        headers=s["headers"],
    )
    _assert_402(r, "scans.mobile.per_period")


@pytest.mark.asyncio
async def test_recon_subdomain_limit_is_clamped(client, project_setup):  # noqa: F811
    settings.PLAN_LIMITS_ENFORCED = True
    s = project_setup
    r = await client.post(
        _url(s), json={"scan_type": "quick", "subdomain_limit": 250}, headers=s["headers"]
    )
    assert r.status_code == 201, r.text
    assert r.json()["subdomain_limit"] == 10


@pytest.mark.asyncio
async def test_invite_hits_users_max(client, project_setup):  # noqa: F811
    settings.PLAN_LIMITS_ENFORCED = True
    s = project_setup
    r = await client.post(
        f"/v1/orgs/{s['org'].id}/members",
        json={"email": "second@t.co", "role": "member"},
        headers=s["headers"],
    )
    d = _assert_402(r, "users.max")
    assert d["limit"] == 1 and d["current"] == 1


@pytest.mark.asyncio
async def test_api_key_cap_and_cli_write(client, project_setup, db_session):  # noqa: F811
    settings.PLAN_LIMITS_ENFORCED = True
    s = project_setup
    # First key is allowed on Free...
    r = await client.post("/v1/auth/api-keys", json={"name": "one"}, headers=s["headers"])
    assert r.status_code == 201, r.text
    # ...the second is not.
    r = await client.post("/v1/auth/api-keys", json={"name": "two"}, headers=s["headers"])
    d = _assert_402(r, "api_keys.max")
    assert d["limit"] == 1 and d["current"] == 1

    # An API-key caller may read but not start scans on Free (cli_write).
    plaintext = f"ss_live_test_{uuid4().hex[:24]}"
    db_session.add(
        APIKey(
            organization_id=s["org"].id,
            name="cli",
            key_prefix=plaintext[:12],
            key_hash=hashlib.sha256(plaintext.encode()).hexdigest(),
        )
    )
    await db_session.commit()
    key_headers = {"Authorization": f"Bearer {plaintext}"}
    r = await client.get(f"/v1/orgs/{s['org'].id}/projects", headers=key_headers)
    assert r.status_code == 200, r.text
    r = await client.post(_url(s), json={"scan_type": "quick"}, headers=key_headers)
    _assert_402(r, "cli_write")


@pytest.mark.asyncio
async def test_compliance_is_gated_by_framework_list(client, project_setup):  # noqa: F811
    settings.PLAN_LIMITS_ENFORCED = True
    s = project_setup
    org = s["org"].id
    r = await client.get(f"/v1/orgs/{org}/compliance/frameworks", headers=s["headers"])
    assert r.status_code == 200, r.text
    assert all(fw["in_plan"] is False for fw in r.json()["frameworks"])
    r = await client.get(f"/v1/orgs/{org}/compliance/posture", headers=s["headers"])
    _assert_402(r, "compliance.frameworks")
    r = await client.get(f"/v1/orgs/{org}/scans/{uuid4()}/compliance/soc2", headers=s["headers"])
    d = _assert_402(r, "compliance.frameworks")
    assert d["current"] == "soc2" and d["limit"] == []
