"""End-to-end tests for /v1/orgs/{org_id}/projects/{id}/verify
+ unit tests for app.services.domain_verify (Task 3.2 Commit 2).
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import select

from app.models.audit import AuditLog
from app.models.identity import Membership, MembershipRole, Organization, User
from app.models.projects import Project
from app.services.auth import create_access_token, hash_password
from tests.conftest import use_org


@pytest_asyncio.fixture
async def project_with_owner(client, db_session):
    """Org + admin + project (un-verified). Returns
    (org, user, project, jwt_headers)."""
    org = Organization(name="Verify Org", slug=f"verifyorg-{uuid4().hex[:8]}")
    db_session.add(org)
    await db_session.flush()
    await use_org(db_session, org.id)
    user = User(
        email=f"v-{uuid4().hex[:6]}@t.co",
        hashed_password=hash_password("VerifyPass-1"),
        full_name="V",
        email_verified=True,
    )
    db_session.add(user)
    await db_session.flush()
    db_session.add(
        Membership(user_id=user.id, organization_id=org.id, role=MembershipRole.ADMIN)
    )
    project = Project(
        organization_id=org.id,
        name="VerifyMe",
        target_url="https://example.com",
        root_domain="example.com",
    )
    db_session.add(project)
    await db_session.commit()
    await db_session.refresh(project)
    headers = {"Authorization": f"Bearer {create_access_token(sub=str(user.id))}"}
    return org, user, project, headers


# ============================================================ DNS TXT mock helper


class _MockTxtRdata:
    """Mimic dnspython's TXT rdata. ``strings`` is tuple[bytes, ...]."""

    def __init__(self, *chunks: bytes):
        self.strings = chunks


async def _make_resolve_returning(records: list[_MockTxtRdata]):
    async def _resolve(name, rdtype, **kwargs):
        return records
    return _resolve


# ============================================================ DNS TXT — happy + failures


@pytest.mark.asyncio
async def test_dns_txt_happy_path(project_with_owner, client, db_session):
    org, _, project, headers = project_with_owner
    token = project.verification_token

    async def _resolve(name, rdtype, **kw):
        return [_MockTxtRdata(token.encode())]

    with patch("app.services.domain_verify.dns.asyncresolver.resolve", _resolve):
        r = await client.post(
            f"/v1/orgs/{org.id}/projects/{project.id}/verify",
            json={"method": "dns_txt"},
            headers=headers,
        )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["verified"] is True
    assert body["method"] == "dns_txt"
    assert body["project"]["domain_verified"] is True
    # DB flipped.
    refreshed = (
        await db_session.execute(select(Project).where(Project.id == project.id))
    ).scalar_one()
    assert refreshed.domain_verified is True


@pytest.mark.asyncio
async def test_dns_txt_wrong_value(project_with_owner, client):
    org, _, project, headers = project_with_owner

    async def _resolve(name, rdtype, **kw):
        return [_MockTxtRdata(b"some-other-token-not-ours")]

    with patch("app.services.domain_verify.dns.asyncresolver.resolve", _resolve):
        r = await client.post(
            f"/v1/orgs/{org.id}/projects/{project.id}/verify",
            json={"method": "dns_txt"},
            headers=headers,
        )
    assert r.status_code == 400
    detail = r.json()["detail"]
    assert detail["failure_reason"] == "dns_token_not_found"
    assert "_shieldscan-verify.example.com" in detail["expected_record"]
    assert project.verification_token in detail["expected_record"]


@pytest.mark.asyncio
async def test_dns_txt_no_answer(project_with_owner, client):
    import dns.resolver

    org, _, project, headers = project_with_owner

    async def _resolve(name, rdtype, **kw):
        raise dns.resolver.NoAnswer()

    with patch("app.services.domain_verify.dns.asyncresolver.resolve", _resolve):
        r = await client.post(
            f"/v1/orgs/{org.id}/projects/{project.id}/verify",
            json={"method": "dns_txt"},
            headers=headers,
        )
    assert r.status_code == 400
    assert r.json()["detail"]["failure_reason"] == "dns_no_answer"


@pytest.mark.asyncio
async def test_dns_txt_nxdomain(project_with_owner, client):
    import dns.resolver

    org, _, project, headers = project_with_owner

    async def _resolve(name, rdtype, **kw):
        raise dns.resolver.NXDOMAIN()

    with patch("app.services.domain_verify.dns.asyncresolver.resolve", _resolve):
        r = await client.post(
            f"/v1/orgs/{org.id}/projects/{project.id}/verify",
            json={"method": "dns_txt"},
            headers=headers,
        )
    assert r.status_code == 400
    assert r.json()["detail"]["failure_reason"] == "dns_nxdomain"


@pytest.mark.asyncio
async def test_dns_txt_lookup_timeout_returns_400_not_hang(
    project_with_owner, client
):
    """dns.exception.Timeout must surface as a 400, not hang the
    request. Verifies the lifetime=5.0 path is wired correctly."""
    import dns.exception

    org, _, project, headers = project_with_owner

    async def _resolve(name, rdtype, **kw):
        raise dns.exception.Timeout()

    with patch("app.services.domain_verify.dns.asyncresolver.resolve", _resolve):
        # Use asyncio.wait_for as a belt-and-suspenders to fail loudly
        # if the request actually hangs.
        r = await asyncio.wait_for(
            client.post(
                f"/v1/orgs/{org.id}/projects/{project.id}/verify",
                json={"method": "dns_txt"},
                headers=headers,
            ),
            timeout=10.0,
        )
    assert r.status_code == 400
    assert r.json()["detail"]["failure_reason"] == "dns_timeout"


@pytest.mark.asyncio
async def test_dns_txt_multiple_records_one_matches(
    project_with_owner, client
):
    """Domains often have multiple TXT records (SPF, DKIM, vendor
    verifications). We must match against ANY record, not require
    exact-single-match."""
    org, _, project, headers = project_with_owner
    token = project.verification_token

    async def _resolve(name, rdtype, **kw):
        return [
            _MockTxtRdata(b"v=spf1 -all"),
            _MockTxtRdata(b"google-site-verification=other-token"),
            _MockTxtRdata(token.encode()),  # the matching one, last
        ]

    with patch("app.services.domain_verify.dns.asyncresolver.resolve", _resolve):
        r = await client.post(
            f"/v1/orgs/{org.id}/projects/{project.id}/verify",
            json={"method": "dns_txt"},
            headers=headers,
        )
    assert r.status_code == 200


# ============================================================ Meta-tag — happy + variations


@pytest.mark.asyncio
async def test_meta_tag_happy_path(project_with_owner, client, db_session):
    org, _, project, headers = project_with_owner
    html = (
        f'<html><head>'
        f'<meta name="shieldscan-verification" content="{project.verification_token}">'
        f'</head></html>'
    )

    async def _get(self, url, **kw):
        m = AsyncMock()
        m.status_code = 200
        m.text = html
        return m

    with patch.object(
        __import__("httpx").AsyncClient, "get", new=_get
    ):
        r = await client.post(
            f"/v1/orgs/{org.id}/projects/{project.id}/verify",
            json={"method": "meta_tag"},
            headers=headers,
        )
    assert r.status_code == 200
    assert r.json()["verified"] is True


@pytest.mark.asyncio
async def test_meta_tag_different_attribute_order(project_with_owner, client):
    """Real-world HTML may emit content="..." before name="..." —
    structured parser handles that; a naive regex would not."""
    org, _, project, headers = project_with_owner
    html = (
        f'<meta content="{project.verification_token}" '
        f'name="shieldscan-verification">'
    )

    async def _get(self, url, **kw):
        m = AsyncMock()
        m.status_code = 200
        m.text = html
        return m

    with patch.object(__import__("httpx").AsyncClient, "get", new=_get):
        r = await client.post(
            f"/v1/orgs/{org.id}/projects/{project.id}/verify",
            json={"method": "meta_tag"},
            headers=headers,
        )
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_meta_tag_single_quoted_attributes(project_with_owner, client):
    org, _, project, headers = project_with_owner
    html = (
        f"<meta name='shieldscan-verification' "
        f"content='{project.verification_token}'>"
    )

    async def _get(self, url, **kw):
        m = AsyncMock()
        m.status_code = 200
        m.text = html
        return m

    with patch.object(__import__("httpx").AsyncClient, "get", new=_get):
        r = await client.post(
            f"/v1/orgs/{org.id}/projects/{project.id}/verify",
            json={"method": "meta_tag"},
            headers=headers,
        )
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_meta_tag_self_closing(project_with_owner, client):
    org, _, project, headers = project_with_owner
    html = (
        f'<meta name="shieldscan-verification" '
        f'content="{project.verification_token}" />'
    )

    async def _get(self, url, **kw):
        m = AsyncMock()
        m.status_code = 200
        m.text = html
        return m

    with patch.object(__import__("httpx").AsyncClient, "get", new=_get):
        r = await client.post(
            f"/v1/orgs/{org.id}/projects/{project.id}/verify",
            json={"method": "meta_tag"},
            headers=headers,
        )
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_meta_tag_wrong_content(project_with_owner, client):
    org, _, project, headers = project_with_owner
    html = '<meta name="shieldscan-verification" content="not-our-token">'

    async def _get(self, url, **kw):
        m = AsyncMock()
        m.status_code = 200
        m.text = html
        return m

    with patch.object(__import__("httpx").AsyncClient, "get", new=_get):
        r = await client.post(
            f"/v1/orgs/{org.id}/projects/{project.id}/verify",
            json={"method": "meta_tag"},
            headers=headers,
        )
    assert r.status_code == 400
    assert r.json()["detail"]["failure_reason"] == "meta_tag_token_mismatch"


@pytest.mark.asyncio
async def test_meta_tag_missing(project_with_owner, client):
    org, _, project, headers = project_with_owner
    html = "<html><head><title>No tag here</title></head></html>"

    async def _get(self, url, **kw):
        m = AsyncMock()
        m.status_code = 200
        m.text = html
        return m

    with patch.object(__import__("httpx").AsyncClient, "get", new=_get):
        r = await client.post(
            f"/v1/orgs/{org.id}/projects/{project.id}/verify",
            json={"method": "meta_tag"},
            headers=headers,
        )
    assert r.status_code == 400
    assert r.json()["detail"]["failure_reason"] == "meta_tag_not_found"


@pytest.mark.asyncio
async def test_meta_tag_redirect_does_not_follow(
    project_with_owner, client
):
    """Security regression guard: ``follow_redirects=False`` is
    load-bearing. A 302 redirect to an attacker-controlled page
    that contains the right tag must NOT verify (because we never
    fetch the redirect target)."""
    org, _, project, headers = project_with_owner

    async def _get(self, url, **kw):
        m = AsyncMock()
        m.status_code = 302  # Found / redirect
        m.text = ""  # body irrelevant; status_code != 200 fails verify
        return m

    with patch.object(__import__("httpx").AsyncClient, "get", new=_get):
        r = await client.post(
            f"/v1/orgs/{org.id}/projects/{project.id}/verify",
            json={"method": "meta_tag"},
            headers=headers,
        )
    assert r.status_code == 400
    assert r.json()["detail"]["failure_reason"] == "http_status_302"


@pytest.mark.asyncio
async def test_meta_tag_http_connect_error(project_with_owner, client):
    import httpx

    org, _, project, headers = project_with_owner

    async def _get(self, url, **kw):
        raise httpx.ConnectError("simulated network failure")

    with patch.object(__import__("httpx").AsyncClient, "get", new=_get):
        r = await client.post(
            f"/v1/orgs/{org.id}/projects/{project.id}/verify",
            json={"method": "meta_tag"},
            headers=headers,
        )
    assert r.status_code == 400
    assert r.json()["detail"]["failure_reason"] == "http_connect_error"


# ============================================================ re-verify failure semantics


@pytest.mark.asyncio
async def test_reverify_missing_record_returns_400_but_keeps_verified_true(
    project_with_owner, client, db_session
):
    """User refinement on Task 3.2 #3: a re-verify whose DNS record
    has been removed must NOT downgrade ``domain_verified`` from True
    to False. DNS is occasionally flaky; one failed re-verify
    shouldn't invalidate historical verification state.
    """
    import dns.resolver

    org, _, project, headers = project_with_owner

    # Pre-flip the project to verified.
    project.domain_verified = True
    await db_session.commit()

    async def _resolve(name, rdtype, **kw):
        raise dns.resolver.NoAnswer()  # record gone

    with patch("app.services.domain_verify.dns.asyncresolver.resolve", _resolve):
        r = await client.post(
            f"/v1/orgs/{org.id}/projects/{project.id}/verify",
            json={"method": "dns_txt"},
            headers=headers,
        )
    assert r.status_code == 400  # current re-verify failed
    refreshed = (
        await db_session.execute(select(Project).where(Project.id == project.id))
    ).scalar_one()
    assert refreshed.domain_verified is True, (
        "re-verify failure must NOT downgrade domain_verified — "
        "DNS is flaky, history shouldn't be invalidated by one miss"
    )


# ============================================================ rate limit / cross-tenant / auth


@pytest.mark.asyncio
async def test_verify_rate_limited_at_5_per_hour_per_project(
    project_with_owner, client
):
    org, _, project, headers = project_with_owner

    async def _resolve(name, rdtype, **kw):
        return [_MockTxtRdata(b"some-token")]

    with patch("app.services.domain_verify.dns.asyncresolver.resolve", _resolve):
        for _ in range(5):
            r = await client.post(
                f"/v1/orgs/{org.id}/projects/{project.id}/verify",
                json={"method": "dns_txt"},
                headers=headers,
            )
            # Within-limit attempts — 400 because token doesn't match,
            # but 400 != 429.
            assert r.status_code == 400

        r = await client.post(
            f"/v1/orgs/{org.id}/projects/{project.id}/verify",
            json={"method": "dns_txt"},
            headers=headers,
        )
        assert r.status_code == 429
        assert r.json()["detail"] == "rate_limit_exceeded"


@pytest.mark.asyncio
async def test_verify_cross_tenant_returns_404(
    project_with_owner, client, db_session
):
    """Org B admin trying /verify on Org A's project → 404 via
    require_org_membership's path-vs-identity match."""
    org_a, _, project_a, _ = project_with_owner

    # Build Org B + admin.
    org_b = Organization(name="OtherV", slug=f"otherv-{uuid4().hex[:8]}")
    db_session.add(org_b)
    await db_session.flush()
    await use_org(db_session, org_b.id)
    user_b = User(
        email=f"vb-{uuid4().hex[:6]}@t.co",
        hashed_password=hash_password("VbPass-1"),
        full_name="VB",
        email_verified=True,
    )
    db_session.add(user_b)
    await db_session.flush()
    db_session.add(
        Membership(user_id=user_b.id, organization_id=org_b.id, role=MembershipRole.ADMIN)
    )
    await db_session.commit()
    headers_b = {"Authorization": f"Bearer {create_access_token(sub=str(user_b.id))}"}

    r = await client.post(
        f"/v1/orgs/{org_a.id}/projects/{project_a.id}/verify",
        json={"method": "dns_txt"},
        headers=headers_b,
    )
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_verify_unauthenticated_returns_401(project_with_owner, client):
    org, _, project, _ = project_with_owner
    r = await client.post(
        f"/v1/orgs/{org.id}/projects/{project.id}/verify",
        json={"method": "dns_txt"},
    )
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_verify_invalid_method_rejected_with_422(
    project_with_owner, client
):
    org, _, project, headers = project_with_owner
    r = await client.post(
        f"/v1/orgs/{org.id}/projects/{project.id}/verify",
        json={"method": "carrier_pigeon"},
        headers=headers,
    )
    assert r.status_code == 422


# ============================================================ audit success + failure


@pytest.mark.asyncio
async def test_verify_success_writes_audit(project_with_owner, client, db_session):
    org, user, project, headers = project_with_owner
    token = project.verification_token

    async def _resolve(name, rdtype, **kw):
        return [_MockTxtRdata(token.encode())]

    with patch("app.services.domain_verify.dns.asyncresolver.resolve", _resolve):
        await client.post(
            f"/v1/orgs/{org.id}/projects/{project.id}/verify",
            json={"method": "dns_txt"},
            headers=headers,
        )
    audits = (
        await db_session.execute(
            select(AuditLog).where(AuditLog.action == "project.domain.verified")
        )
    ).scalars().all()
    assert len(audits) == 1
    assert audits[0].actor_id == user.id
    assert audits[0].details == {"method": "dns_txt"}


@pytest.mark.asyncio
async def test_verify_failure_writes_audit_with_reason(
    project_with_owner, client, db_session
):
    """Per Task 3.2 decision #4: audit failures too. Useful ops
    intel — sustained failures = customer DNS issue."""
    import dns.resolver

    org, user, project, headers = project_with_owner

    async def _resolve(name, rdtype, **kw):
        raise dns.resolver.NXDOMAIN()

    with patch("app.services.domain_verify.dns.asyncresolver.resolve", _resolve):
        await client.post(
            f"/v1/orgs/{org.id}/projects/{project.id}/verify",
            json={"method": "dns_txt"},
            headers=headers,
        )
    audits = (
        await db_session.execute(
            select(AuditLog).where(
                AuditLog.action == "project.domain.verification_failed"
            )
        )
    ).scalars().all()
    assert len(audits) == 1
    assert audits[0].details == {"method": "dns_txt", "reason": "dns_nxdomain"}
