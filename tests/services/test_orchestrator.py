"""Tests for ``app.services.orchestrator.ScanOrchestrator`` (Task 4.2).

Eight tests pinning the dispatch contract:

  1. full_web → 8 ScanJob rows persisted, 8 queue items dispatched
  2. mobile → one mobsf job + payload.mobile_config populated
  3. idempotency_key format: {scan_id}:{tool}:{unix_ts}
  4. Job payload matches SPEC §7.1 shape
  5. payload.auth is None — ADR-015 deferral pin
  6. PUBLIC scan type → UnsupportedScanTypeError
  7. Invalid priority bubbles ValueError from ScanQueue
  8. Commit-then-dispatch ordering — DB row persists if Redis dispatch
     fails; Redis dispatch happens AFTER PG commit (H.3 contract).
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from sqlalchemy import select

from app.dependencies import AuthIdentity
from app.models.identity import APIKey, Membership, MembershipRole, Organization, User
from app.models.mobile import MobilePlatform, MobileUpload
from app.models.projects import Project
from app.models.scans import Scan, ScanJob, ScanStatus, ScanType
from app.services.api_keys import generate_api_key
from app.services.auth import hash_password
from app.services.orchestrator import (
    SCAN_TYPE_TOOLS,
    ScanOrchestrator,
    ScanPriority,
    UnsupportedScanTypeError,
)
from tests.conftest import use_org


# ---------------------------------------------------------------- fixtures


@pytest_asyncio.fixture
async def web_scan(db_session):
    """Persisted Scan + Project + Org + User for a full_web flow.
    Returns dict with handles tests need."""
    org = Organization(name="Disp Org", slug=f"disp-{uuid4().hex[:8]}")
    db_session.add(org)
    await db_session.flush()
    await use_org(db_session, org.id)

    user = User(
        email=f"d-{uuid4().hex[:6]}@t.co",
        hashed_password=hash_password("DispPass-1"),
        full_name="D",
        email_verified=True,
    )
    db_session.add(user)
    await db_session.flush()
    db_session.add(
        Membership(user_id=user.id, organization_id=org.id, role=MembershipRole.ADMIN)
    )

    project = Project(
        organization_id=org.id,
        name="DispApp",
        target_url="https://disp.example.com",
        root_domain="example.com",
        domain_verified=True,
    )
    db_session.add(project)
    await db_session.flush()

    scan = Scan(
        organization_id=org.id,
        project_id=project.id,
        scan_type=ScanType.FULL_WEB,
        status=ScanStatus.QUEUED,
        priority="normal",
        config={"depth": "standard"},
    )
    db_session.add(scan)
    await db_session.commit()
    await db_session.refresh(scan)
    # Ensure project is loaded onto the scan so payload-build doesn't
    # trigger lazy-load (would raise MissingGreenlet in async).
    scan.project = project  # type: ignore[attr-defined]

    identity = AuthIdentity(
        kind="jwt",
        organization_id=org.id,
        user=user,
        role=MembershipRole.ADMIN,
    )
    return {
        "org": org,
        "project": project,
        "user": user,
        "scan": scan,
        "identity": identity,
    }


@pytest_asyncio.fixture
async def mobile_scan(db_session):
    """Persisted mobile-scan flow: project + uploaded APK + scan."""
    org = Organization(name="Mob Disp Org", slug=f"mdisp-{uuid4().hex[:8]}")
    db_session.add(org)
    await db_session.flush()
    await use_org(db_session, org.id)

    user = User(
        email=f"md-{uuid4().hex[:6]}@t.co",
        hashed_password=hash_password("MdPass-1"),
        full_name="MD",
        email_verified=True,
    )
    db_session.add(user)
    await db_session.flush()
    db_session.add(
        Membership(user_id=user.id, organization_id=org.id, role=MembershipRole.ADMIN)
    )

    project = Project(
        organization_id=org.id,
        name="MobApp",
        target_url="https://mob.example.com",
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
        file_size_bytes=1024,
        platform=MobilePlatform.ANDROID,
        r2_key=f"mobile-uploads/{org.id}/{project.id}/{uuid4()}.apk",
    )
    db_session.add(upload)
    await db_session.flush()

    scan = Scan(
        organization_id=org.id,
        project_id=project.id,
        scan_type=ScanType.MOBILE,
        status=ScanStatus.QUEUED,
        priority="high",
        mobile_upload_id=upload.id,
        config={"analysis_type": "both"},
    )
    db_session.add(scan)
    await db_session.commit()
    await db_session.refresh(scan)
    scan.project = project  # type: ignore[attr-defined]

    identity = AuthIdentity(
        kind="jwt",
        organization_id=org.id,
        user=user,
        role=MembershipRole.ADMIN,
    )
    return {
        "org": org,
        "project": project,
        "user": user,
        "upload": upload,
        "scan": scan,
        "identity": identity,
    }


# ---------------------------------------------------------------- 1. full_web → 8 jobs


@pytest.mark.asyncio
async def test_dispatch_full_web_creates_8_jobs(web_scan, db_session, fake_redis):
    s = web_scan
    orch = ScanOrchestrator(db_session, fake_redis)
    jobs = await orch.dispatch(s["scan"], s["identity"])

    assert len(jobs) == 8
    expected = SCAN_TYPE_TOOLS[ScanType.FULL_WEB]
    assert sorted(j.engine for j in jobs) == sorted(expected)

    # Persisted in DB.
    db_jobs = (
        await db_session.execute(
            select(ScanJob).where(ScanJob.scan_id == s["scan"].id)
        )
    ).scalars().all()
    assert len(db_jobs) == 8

    # All 8 dispatched onto the queue.
    queued = []
    for _ in range(8):
        item = await fake_redis.brpop("shieldscan:queue:normal", timeout=1)
        assert item is not None
        queued.append(json.loads(item[1]))
    assert len(queued) == 8
    assert {q["engine"] for q in queued} == set(expected)


# ---------------------------------------------------------------- 2. mobile branch


@pytest.mark.asyncio
async def test_dispatch_mobile_creates_one_mobsf_job_with_mobile_config(
    mobile_scan, db_session, fake_redis
):
    s = mobile_scan
    orch = ScanOrchestrator(db_session, fake_redis)
    jobs = await orch.dispatch(s["scan"], s["identity"])

    assert len(jobs) == 1
    assert jobs[0].engine == "mobsf"

    item = await fake_redis.brpop("shieldscan:queue:high", timeout=1)
    payload = json.loads(item[1])
    assert payload["engine"] == "mobsf"
    assert payload["mobile_config"]["upload_ref"].startswith("r2://")
    assert payload["mobile_config"]["platform"] == "android"
    # Explicit scan.config override flows through verbatim (this fixture
    # sets analysis_type="both" — used to forward-pin v2 dynamic+static
    # combined analysis once shieldscan-engine MobSF consumer supports it).
    assert payload["mobile_config"]["analysis_type"] == "both"
    assert payload["target"]["target_type"] == "mobile"


# ---------------------------------------------------------------- 2b. mobile analysis_type default


@pytest.mark.asyncio
async def test_dispatch_mobile_analysis_type_defaults_to_static(
    mobile_scan, db_session, fake_redis
):
    """D-PLAN-7 Path (c): when scan.config carries no analysis_type override,
    the orchestrator emits "static" — matching the engine-side MobSF
    consumer v1 lock (dynamic + source-tree forward-pinned)."""
    s = mobile_scan
    # Clear the analysis_type override the fixture seeds.
    s["scan"].config = {}
    db_session.add(s["scan"])
    await db_session.commit()
    await db_session.refresh(s["scan"])
    s["scan"].project = s["scan"].project  # rehydrate relationship attr

    orch = ScanOrchestrator(db_session, fake_redis)
    jobs = await orch.dispatch(s["scan"], s["identity"])
    assert len(jobs) == 1

    item = await fake_redis.brpop("shieldscan:queue:high", timeout=1)
    payload = json.loads(item[1])
    assert payload["mobile_config"]["analysis_type"] == "static"


# ---------------------------------------------------------------- 3. idempotency key format


@pytest.mark.asyncio
async def test_dispatch_idempotency_key_format(web_scan, db_session, fake_redis):
    s = web_scan
    orch = ScanOrchestrator(db_session, fake_redis)
    jobs = await orch.dispatch(s["scan"], s["identity"])
    for job in jobs:
        parts = job.idempotency_key.split(":")
        assert len(parts) == 3, f"unexpected key shape: {job.idempotency_key}"
        scan_id_part, engine_part, ts_part = parts
        assert scan_id_part == str(s["scan"].id)
        assert engine_part == job.engine
        assert ts_part.isdigit()


# ---------------------------------------------------------------- 4. payload SPEC §7.1 shape


@pytest.mark.asyncio
async def test_dispatch_payload_matches_spec_71_shape(web_scan, db_session, fake_redis):
    s = web_scan
    orch = ScanOrchestrator(db_session, fake_redis)
    await orch.dispatch(s["scan"], s["identity"])

    item = await fake_redis.brpop("shieldscan:queue:normal", timeout=1)
    payload = json.loads(item[1])
    # SPEC §7.1 fields:
    for key in (
        "id",
        "scan_id",
        "organization_id",
        "engine",
        "idempotency_key",
        "target",
        "auth",
        "config",
        "mobile_config",
        "callback_stream",
        "created_at",
    ):
        assert key in payload, f"missing SPEC §7.1 field: {key}"
    assert payload["target"]["url"] == s["project"].target_url
    assert payload["target"]["domain_verified"] is True
    assert payload["callback_stream"] == f"shieldscan:progress:{s['scan'].id}"
    # ISO timestamp ends in Z (SPEC §7.1 example).
    assert payload["created_at"].endswith("Z")


# ---------------------------------------------------------------- 5. auth=None pin (ADR-015 deferral)


@pytest.mark.asyncio
async def test_dispatch_payload_auth_is_null_pending_adr_015(
    web_scan, db_session, fake_redis
):
    """Negative regression pin. ``payload.auth`` is intentionally None
    until ADR-015 enables decrypted-credential transit. Don't 'helpfully'
    populate this field without writing the ADR first."""
    s = web_scan
    orch = ScanOrchestrator(db_session, fake_redis)
    await orch.dispatch(s["scan"], s["identity"])
    item = await fake_redis.brpop("shieldscan:queue:normal", timeout=1)
    payload = json.loads(item[1])
    assert payload["auth"] is None


# ---------------------------------------------------------------- 6. PUBLIC scan type rejected


@pytest.mark.asyncio
async def test_dispatch_unsupported_public_scan_type_raises(
    web_scan, db_session, fake_redis
):
    """Public scans live in a separate `public_scans` table per
    ADDENDUM-CRITICAL-5 §2.4 and are NOT routed through this
    orchestrator. Pin via fail-loud raise."""
    s = web_scan
    s["scan"].scan_type = ScanType.PUBLIC
    orch = ScanOrchestrator(db_session, fake_redis)
    with pytest.raises(UnsupportedScanTypeError):
        await orch.dispatch(s["scan"], s["identity"])


# ---------------------------------------------------------------- 7. Invalid priority


@pytest.mark.asyncio
async def test_dispatch_invalid_priority_raises(web_scan, db_session, fake_redis):
    s = web_scan
    s["scan"].priority = "URGENT"  # not in ScanPriority
    orch = ScanOrchestrator(db_session, fake_redis)
    with pytest.raises(ValueError):
        await orch.dispatch(s["scan"], s["identity"])


# ---------------------------------------------------------------- 8. commit-then-dispatch (H.3)


@pytest.mark.asyncio
async def test_dispatch_commits_before_redis_dispatch(
    web_scan, db_session, fake_redis
):
    """Commit-then-dispatch ordering (Task 4.2 H.3 + ADR-013).

    If Redis dispatch fails, the DB rows MUST remain persisted (commit
    happened first). Customer sees a 'ghost queued' scan they can
    triage. M5+ retry janitor will recover.

    Failure mode is visible-failure > silent-failure for MVP.
    """
    s = web_scan
    orch = ScanOrchestrator(db_session, fake_redis)

    # Replace the queue.dispatch with a mock that raises.
    orch.queue.dispatch = AsyncMock(  # type: ignore[method-assign]
        side_effect=ConnectionError("redis blip simulated")
    )

    with pytest.raises(ConnectionError):
        await orch.dispatch(s["scan"], s["identity"])

    # DB rows persisted despite Redis failure.
    persisted = (
        await db_session.execute(
            select(ScanJob).where(ScanJob.scan_id == s["scan"].id)
        )
    ).scalars().all()
    assert len(persisted) == 8, (
        f"commit-then-dispatch contract: ScanJob rows must persist "
        f"even when queue dispatch fails — got {len(persisted)} rows"
    )

    # Audit row was emitted as part of the orchestrator's transaction
    # (which committed before the queue.dispatch call).
    from app.models.audit import AuditLog
    audits = (
        await db_session.execute(
            select(AuditLog).where(AuditLog.action == "scan.dispatched")
        )
    ).scalars().all()
    assert len(audits) == 1
    assert audits[0].details["job_count"] == 8
