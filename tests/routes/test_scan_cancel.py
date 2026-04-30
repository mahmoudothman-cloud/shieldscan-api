"""End-to-end tests for DELETE /v1/orgs/{org_id}/scans/{scan_id} (Task 4.5).

11 tests pinning the cancel-endpoint contract:

  Happy paths (2):
   1. cancel queued scan → 204 + status=CANCELED + audit + Redis publish
   2. cancel running scan → same shape

  Terminal-state guards (2):
   3. cancel COMPLETED → 409 scan_already_terminal
   4. cancel FAILED → 409 scan_already_terminal

  Idempotency (1):
   5. cancel already-CANCELED → 204 + fresh audit row (audit-on-event)

  Auth + tenant (3):
   6. cross-tenant scan_id → 404 (existence-hiding)
   7. unauthenticated → 401
   8. cancel via API key → 204 (require_org_membership accepts both)

  Behavior pins (3):
   9.  cancel publishes to shieldscan:cancel:{scan_id} with correct shape
  10. cancel via API key → audit details has api_key_prefix, actor_id None
  11. cancel emits SCAN_CANCELED audit with full details shape
"""

from __future__ import annotations

import asyncio
import json
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from sqlalchemy import select

from app.models.audit import AuditLog
from app.models.identity import APIKey, Membership, MembershipRole, Organization, User
from app.models.projects import Project
from app.models.scans import Scan, ScanStatus, ScanType
from app.services.api_keys import generate_api_key
from app.services.auth import create_access_token, hash_password
from tests.conftest import use_org


# ---------------------------------------------------------------- fixtures


@pytest_asyncio.fixture
async def cancellable_scan(client, db_session):
    """Org + admin + project + queued scan + JWT headers + a live API key.
    Scan is in QUEUED state, ready to cancel."""
    org = Organization(name="Cancel Org", slug=f"cn-{uuid4().hex[:8]}")
    db_session.add(org)
    await db_session.flush()
    await use_org(db_session, org.id)

    user = User(
        email=f"c-{uuid4().hex[:6]}@t.co",
        hashed_password=hash_password("CnPass-1"),
        full_name="C",
        email_verified=True,
    )
    db_session.add(user)
    await db_session.flush()
    db_session.add(
        Membership(user_id=user.id, organization_id=org.id, role=MembershipRole.ADMIN)
    )

    project = Project(
        organization_id=org.id,
        name="CnApp",
        target_url="https://cn.example.com",
        root_domain="example.com",
        domain_verified=True,
    )
    db_session.add(project)
    await db_session.flush()

    scan = Scan(
        organization_id=org.id,
        project_id=project.id,
        scan_type=ScanType.QUICK,
        status=ScanStatus.QUEUED,
        priority="normal",
        config={},
    )
    db_session.add(scan)

    plain, key_hash, prefix = generate_api_key("live")
    api_key = APIKey(
        organization_id=org.id,
        name="ci",
        key_prefix=prefix,
        key_hash=key_hash,
    )
    db_session.add(api_key)

    await db_session.commit()
    await db_session.refresh(scan)
    await db_session.refresh(api_key)

    return {
        "org": org,
        "user": user,
        "project": project,
        "scan": scan,
        "api_key": api_key,
        "headers": {"Authorization": f"Bearer {create_access_token(sub=str(user.id))}"},
        "api_key_headers": {"Authorization": f"Bearer {plain}"},
    }


@pytest_asyncio.fixture
async def other_org_scan(db_session):
    """A second org with its own scan — used for cross-tenant tests."""
    org = Organization(name="Other Cn Org", slug=f"oth-{uuid4().hex[:8]}")
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
        name="OthApp",
        target_url="https://oth.example.com",
        root_domain="example.com",
        domain_verified=True,
    )
    db_session.add(project)
    await db_session.flush()
    scan = Scan(
        organization_id=org.id,
        project_id=project.id,
        scan_type=ScanType.QUICK,
        status=ScanStatus.QUEUED,
        priority="normal",
        config={},
    )
    db_session.add(scan)
    await db_session.commit()
    await db_session.refresh(scan)
    return {"org": org, "scan": scan}


def _url(s):
    return f"/v1/orgs/{s['org'].id}/scans/{s['scan'].id}"


# ============================================================ 1-2. happy paths


@pytest.mark.asyncio
async def test_cancel_queued_scan_returns_204(cancellable_scan, client, db_session, fake_redis):
    s = cancellable_scan
    r = await client.delete(_url(s), headers=s["headers"])
    assert r.status_code == 204, r.text
    assert r.content == b""

    # Status flipped in DB.
    await db_session.refresh(s["scan"])
    assert s["scan"].status == ScanStatus.CANCELED


@pytest.mark.asyncio
async def test_cancel_running_scan_returns_204(cancellable_scan, client, db_session):
    s = cancellable_scan
    s["scan"].status = ScanStatus.RUNNING
    await db_session.commit()
    r = await client.delete(_url(s), headers=s["headers"])
    assert r.status_code == 204
    await db_session.refresh(s["scan"])
    assert s["scan"].status == ScanStatus.CANCELED


# ============================================================ 3-4. terminal-final guard


@pytest.mark.asyncio
async def test_cancel_completed_scan_returns_409(cancellable_scan, client, db_session):
    s = cancellable_scan
    s["scan"].status = ScanStatus.COMPLETED
    await db_session.commit()
    r = await client.delete(_url(s), headers=s["headers"])
    assert r.status_code == 409
    assert r.json()["detail"] == "scan_already_terminal"


@pytest.mark.asyncio
async def test_cancel_failed_scan_returns_409(cancellable_scan, client, db_session):
    s = cancellable_scan
    s["scan"].status = ScanStatus.FAILED
    await db_session.commit()
    r = await client.delete(_url(s), headers=s["headers"])
    assert r.status_code == 409
    assert r.json()["detail"] == "scan_already_terminal"


# ============================================================ 5. idempotent already-CANCELED


@pytest.mark.asyncio
async def test_cancel_already_canceled_returns_204_with_fresh_audit(
    cancellable_scan, client, db_session
):
    """Audit-on-event regression guard: each cancel ATTEMPT emits a
    fresh audit row, even when the resulting state is unchanged.
    Pin against future "helpful" audit-dedupe optimization. Same
    discipline as Task 3.2's re-verify pin."""
    s = cancellable_scan
    r1 = await client.delete(_url(s), headers=s["headers"])
    assert r1.status_code == 204
    r2 = await client.delete(_url(s), headers=s["headers"])
    assert r2.status_code == 204

    audits = (
        await db_session.execute(
            select(AuditLog).where(
                AuditLog.action == "scan.canceled",
                AuditLog.resource_id == s["scan"].id,
            )
        )
    ).scalars().all()
    assert len(audits) == 2, (
        f"each cancel attempt must emit a fresh audit row; got {len(audits)}"
    )


# ============================================================ 6-8. auth + tenant


@pytest.mark.asyncio
async def test_cancel_cross_tenant_returns_404(cancellable_scan, other_org_scan, client):
    """Caller in their own org's path with another org's scan_id — 404
    (existence-hiding). Other-org's scan should be invisible."""
    s = cancellable_scan
    other = other_org_scan
    url = f"/v1/orgs/{s['org'].id}/scans/{other['scan'].id}"
    r = await client.delete(url, headers=s["headers"])
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_cancel_unauthenticated_returns_401(cancellable_scan, client):
    s = cancellable_scan
    r = await client.delete(_url(s))
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_cancel_via_api_key_succeeds(cancellable_scan, client, db_session):
    s = cancellable_scan
    r = await client.delete(_url(s), headers=s["api_key_headers"])
    assert r.status_code == 204
    await db_session.refresh(s["scan"])
    assert s["scan"].status == ScanStatus.CANCELED


# ============================================================ 9. Redis publish


@pytest.mark.asyncio
async def test_cancel_publishes_to_redis_channel(cancellable_scan, client, fake_redis):
    """Cancel signal lands on shieldscan:cancel:{scan_id} per SPEC §7.4
    + ADR-014 (Pub/Sub for one-shot live-only signals)."""
    s = cancellable_scan
    received_event: dict | None = None

    pubsub = fake_redis.pubsub()
    await pubsub.subscribe(f"shieldscan:cancel:{s['scan'].id}")

    async def consume():
        nonlocal received_event
        async for message in pubsub.listen():
            if message["type"] == "message":
                received_event = json.loads(message["data"])
                break

    task = asyncio.create_task(consume())
    await asyncio.sleep(0.05)
    r = await client.delete(_url(s), headers=s["headers"])
    assert r.status_code == 204
    await asyncio.wait_for(task, timeout=3.0)

    assert received_event is not None
    assert received_event["event_type"] == "cancel_requested"
    assert received_event["scan_id"] == str(s["scan"].id)
    assert received_event["reason"] == "user_requested"
    await pubsub.aclose()


# ============================================================ 10. API-key audit shape


@pytest.mark.asyncio
async def test_cancel_via_api_key_audits_with_key_prefix(
    cancellable_scan, client, db_session
):
    """Dual-credential audit shape: API-key path → actor_id is None,
    details carry api_key_prefix. Same convention as Task 3.3 mobile
    upload + Task 3.X credentials API-key audit."""
    s = cancellable_scan
    r = await client.delete(_url(s), headers=s["api_key_headers"])
    assert r.status_code == 204

    audits = (
        await db_session.execute(
            select(AuditLog).where(
                AuditLog.action == "scan.canceled",
                AuditLog.resource_id == s["scan"].id,
            )
        )
    ).scalars().all()
    assert len(audits) == 1
    a = audits[0]
    assert a.actor_id is None
    assert a.details["api_key_prefix"] == s["api_key"].key_prefix


# ============================================================ 11. JWT audit details shape


@pytest.mark.asyncio
async def test_cancel_emits_scan_canceled_audit_with_full_details(
    cancellable_scan, client, db_session
):
    """Pin the full audit details shape per H.5:
    {scan_type, previous_status, reason}. Self-explanatory without
    a join to scans.

    JWT path (no api_key_prefix in details)."""
    s = cancellable_scan
    s["scan"].status = ScanStatus.RUNNING
    await db_session.commit()
    r = await client.delete(_url(s), headers=s["headers"])
    assert r.status_code == 204

    audits = (
        await db_session.execute(
            select(AuditLog).where(
                AuditLog.action == "scan.canceled",
                AuditLog.resource_id == s["scan"].id,
            )
        )
    ).scalars().all()
    assert len(audits) == 1
    a = audits[0]
    assert a.actor_id == s["user"].id
    assert a.organization_id == s["org"].id
    assert a.details["scan_type"] == "quick"
    assert a.details["previous_status"] == "running"
    assert a.details["reason"] == "user_requested"
    assert "api_key_prefix" not in a.details
