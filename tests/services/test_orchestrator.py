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
from app.models.audit import AuditLog
from app.models.mobile import MobilePlatform, MobileUpload
from app.models.projects import Project, ProjectCredential
from app.models.recon import AttackSurface, SubdomainStatus
from app.models.scans import Scan, ScanJob, ScanStatus, ScanType
from app.services.api_keys import generate_api_key
from app.services.audit import ScanAction
from app.services.auth import hash_password
from app.services.credentials import encrypt_credential
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
async def test_dispatch_full_web_phase1_recon_only(web_scan, db_session, fake_redis):
    """M8.1β.2 ADR-028: web-ScanType phase-1 dispatch creates a SINGLE
    recon ScanJob (engine="recon"), NOT the full SCAN_TYPE_TOOLS set.
    The per-(target, tool) tool jobs are dispatched at phase-2
    (dispatch_phase2) after recon emits EventAttackSurface."""
    s = web_scan
    orch = ScanOrchestrator(db_session, fake_redis)
    jobs = await orch.dispatch(s["scan"], s["identity"])

    assert len(jobs) == 1, "phase-1 web dispatch is recon-only"
    assert jobs[0].engine == "recon"
    assert jobs[0].idempotency_key == f"{s['scan'].id}:recon:{jobs[0].idempotency_key.rsplit(':', 1)[1]}"

    # Persisted in DB.
    db_jobs = (
        await db_session.execute(
            select(ScanJob).where(ScanJob.scan_id == s["scan"].id)
        )
    ).scalars().all()
    assert len(db_jobs) == 1
    assert db_jobs[0].engine == "recon"

    # The single recon job is queued.
    item = await fake_redis.brpop("shieldscan:queue:normal", timeout=1)
    assert item is not None
    q = json.loads(item[1])
    assert q["engine"] == "recon"
    # No second job on the queue.
    assert await fake_redis.brpop("shieldscan:queue:normal", timeout=1) is None


# ---------------------------------------------------------------- Source-Ingestion Fix: trivy-fs source threading
#
# Per TOOL-ARCH §3.2 addendum (shieldscan-docs 9d6ab25). FULL_WEB_SOURCE
# and FULL_SPECTRUM dispatch ``trivy-fs`` (which clones source per
# Q-WIRE engine-clones lock). Orchestrator must thread
# ``Project.source_repo_url`` into the wire ``target`` block for these
# ScanTypes; other ScanTypes must NOT carry the field. Drift #54
# root-cause repair: column was orphaned since M1; this test pins the
# new threading invariant.


@pytest.mark.asyncio
async def test_dispatch_threads_source_repo_url_for_full_web_source(
    db_session, fake_redis
):
    """FULL_WEB_SOURCE threads scan.project.source_repo_url into the
    dispatched payload's target block."""
    org = Organization(name="SI Org", slug=f"si-{uuid4().hex[:8]}")
    db_session.add(org)
    await db_session.flush()
    await use_org(db_session, org.id)

    user = User(
        email=f"si-{uuid4().hex[:6]}@t.co",
        hashed_password=hash_password("SiPass-1"),
        full_name="SI",
        email_verified=True,
    )
    db_session.add(user)
    await db_session.flush()
    db_session.add(
        Membership(user_id=user.id, organization_id=org.id, role=MembershipRole.ADMIN)
    )

    project = Project(
        organization_id=org.id,
        name="SrcApp",
        target_url="https://src.example.com",
        root_domain="example.com",
        domain_verified=True,
        source_repo_url="https://github.com/OWASP/NodeGoat.git",
    )
    db_session.add(project)
    await db_session.flush()

    scan = Scan(
        organization_id=org.id,
        project_id=project.id,
        scan_type=ScanType.FULL_WEB_SOURCE,
        status=ScanStatus.QUEUED,
        priority="normal",
        config={"depth": "standard"},
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
    orch = ScanOrchestrator(db_session, fake_redis)

    # M8.1β.2 ADR-028: the source_repo_url threading invariant (Drift #54)
    # now lives at PHASE-2 — FULL_WEB_SOURCE phase-1 dispatches only the
    # recon job; the trivy-fs tool job (which carries source_repo_url) is
    # dispatched at phase-2 after recon discovers live targets.
    phase1 = await orch.dispatch(scan, identity)
    assert len(phase1) == 1 and phase1[0].engine == "recon"
    # drain the recon job off the queue.
    assert await fake_redis.brpop("shieldscan:queue:normal", timeout=1) is not None

    # Seed one live attack-surface row (recon-discovered subdomain).
    db_session.add(
        AttackSurface(
            organization_id=org.id,
            scan_id=scan.id,
            root_domain="example.com",
            subdomain="src.example.com",
            full_url="https://src.example.com",
            status=SubdomainStatus.LIVE,
            status_code=200,
        )
    )
    await db_session.commit()

    # Phase-2 dispatch: per-(target, tool) jobs carry source_repo_url.
    phase2 = await orch.dispatch_phase2(scan_id=scan.id)
    expected_tools = [
        t for t in SCAN_TYPE_TOOLS[ScanType.FULL_WEB_SOURCE] if t != "recon"
    ]
    # 1 live target × N non-recon tools.
    assert len(phase2) == len(expected_tools)

    queued = []
    for _ in range(len(phase2)):
        item = await fake_redis.brpop("shieldscan:queue:normal", timeout=1)
        assert item is not None
        queued.append(json.loads(item[1]))
    assert all(
        q["target"].get("source_repo_url")
        == "https://github.com/OWASP/NodeGoat.git"
        for q in queued
    ), [q["target"] for q in queued]
    # Phase-2 jobs scan the discovered subdomain, not the root.
    assert all(q["target"]["url"] == "https://src.example.com" for q in queued)


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
async def test_dispatch_mobile_emits_signed_fetch_url_alongside_upload_ref(
    mobile_scan, db_session, fake_redis, monkeypatch
):
    """MobSF R2 pre-signed URL task: Q1 (β) sibling-field decision —
    orchestrator emits both ``upload_ref`` (legacy r2://) AND
    ``signed_fetch_url`` (pre-signed HTTPS URL) during migration window
    per ADR-013 Pre-Signed URL Extension addendum at 8f71b01."""
    from app.services import r2 as r2_module

    fake_signed = "https://example.r2.cloudflarestorage.com/signed?X-Amz-Sig=deadbeef"

    async def fake_generate(r2_key: str, expiry: int = 600) -> str:
        # Echo the inputs into the returned URL for assertion.
        return f"{fake_signed}&key={r2_key}&exp={expiry}"

    monkeypatch.setattr(r2_module, "generate_presigned_get_url", fake_generate)
    # Patch the orchestrator's imported reference too (module-level alias).
    from app.services import orchestrator as orch_module
    monkeypatch.setattr(orch_module, "generate_presigned_get_url", fake_generate)

    s = mobile_scan
    orch = ScanOrchestrator(db_session, fake_redis)
    await orch.dispatch(s["scan"], s["identity"])

    item = await fake_redis.brpop("shieldscan:queue:high", timeout=1)
    payload = json.loads(item[1])
    # Q1 (β) sibling-field: BOTH fields populated during migration.
    assert payload["mobile_config"]["upload_ref"].startswith("r2://")
    assert payload["mobile_config"]["signed_fetch_url"].startswith("https://")
    assert s["upload"].r2_key in payload["mobile_config"]["signed_fetch_url"]
    # Q2 (a) 600s default expiry passed through.
    assert "exp=600" in payload["mobile_config"]["signed_fetch_url"]


@pytest.mark.asyncio
async def test_dispatch_emits_presigned_url_generated_audit_row(
    mobile_scan, db_session, fake_redis, monkeypatch
):
    """MobSF R2 pre-signed URL task Q5 (a): orchestrator emits
    ``SCAN_PRESIGNED_URL_GENERATED`` AuditLog row at URL-generation-time
    (analog to ADR-015 ``SCAN_CREDENTIAL_DECRYPTED`` forensics posture).
    ScanAction policy: scan-level only, NOT per-job."""
    from app.services import orchestrator as orch_module

    async def fake_generate(r2_key: str, expiry: int = 600) -> str:
        return f"https://example.r2/signed?k={r2_key}"

    monkeypatch.setattr(orch_module, "generate_presigned_get_url", fake_generate)

    s = mobile_scan
    orch = ScanOrchestrator(db_session, fake_redis)
    await orch.dispatch(s["scan"], s["identity"])

    audit_rows = (
        await db_session.execute(
            select(AuditLog).where(
                AuditLog.action == ScanAction.SCAN_PRESIGNED_URL_GENERATED.value,
                AuditLog.resource_id == s["scan"].id,
            )
        )
    ).scalars().all()
    assert len(audit_rows) == 1, "exactly one SCAN_PRESIGNED_URL_GENERATED row per mobile dispatch"
    row = audit_rows[0]
    assert row.details["r2_key"] == s["upload"].r2_key
    assert row.details["expiry_seconds"] == 600
    assert row.actor_id == s["user"].id


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


# ---------------------------------------------------------------- 5. ADR-015 enablement — auth-block emission


@pytest.mark.asyncio
async def test_dispatch_payload_auth_is_null_for_credential_less_project(
    web_scan, db_session, fake_redis
):
    """ADR-015 enablement preserves the legacy ``auth: None`` path
    for credential-less projects (the ``web_scan`` fixture creates
    no ProjectCredential). Replaces the historical
    ``test_dispatch_payload_auth_is_null_pending_adr_015`` regression
    pin, which prevented premature implementation pre-ADR-015 landing.
    """
    s = web_scan
    orch = ScanOrchestrator(db_session, fake_redis)
    await orch.dispatch(s["scan"], s["identity"])
    item = await fake_redis.brpop("shieldscan:queue:normal", timeout=1)
    payload = json.loads(item[1])
    assert payload["auth"] is None


@pytest.mark.asyncio
async def test_dispatch_payload_auth_emits_decrypted_credential_when_present(
    web_scan, db_session, fake_redis
):
    """ADR-015 enablement: when a ProjectCredential exists for the
    scan's project, orchestrator decrypts + emits the credential in
    ``payload["auth"]`` per SPEC §13 ADR-015. Q3 (a) discriminator
    translation: DB ``auth_type`` → wire ``type``."""
    s = web_scan
    credential = ProjectCredential(
        organization_id=s["org"].id,
        project_id=s["project"].id,
        auth_type="cookie",
        encrypted_data=encrypt_credential({"data": "session=test123"}),
    )
    db_session.add(credential)
    await db_session.commit()

    orch = ScanOrchestrator(db_session, fake_redis)
    await orch.dispatch(s["scan"], s["identity"])

    item = await fake_redis.brpop("shieldscan:queue:normal", timeout=1)
    payload = json.loads(item[1])
    assert payload["auth"] is not None
    assert payload["auth"]["type"] == "cookie"
    assert payload["auth"]["data"] == "session=test123"
    assert "fields" not in payload["auth"]


@pytest.mark.asyncio
async def test_dispatch_payload_auth_emits_form_credential_with_fields(
    web_scan, db_session, fake_redis
):
    """ADR-015 enablement: form-type credentials carry ``fields``
    map alongside ``data`` per design doc §3.1 + ADR-015 §13
    AuthType coverage."""
    s = web_scan
    credential = ProjectCredential(
        organization_id=s["org"].id,
        project_id=s["project"].id,
        auth_type="form",
        encrypted_data=encrypt_credential(
            {
                "data": "https://example.com/login",
                "fields": {"username": "admin", "password": "test"},
            }
        ),
    )
    db_session.add(credential)
    await db_session.commit()

    orch = ScanOrchestrator(db_session, fake_redis)
    await orch.dispatch(s["scan"], s["identity"])

    item = await fake_redis.brpop("shieldscan:queue:normal", timeout=1)
    payload = json.loads(item[1])
    assert payload["auth"]["type"] == "form"
    assert payload["auth"]["fields"] == {"username": "admin", "password": "test"}


@pytest.mark.asyncio
async def test_dispatch_emits_credential_access_audit_row(
    web_scan, db_session, fake_redis
):
    """ADR-015 enablement Q6 (a): orchestrator emits one
    ``SCAN_CREDENTIAL_DECRYPTED`` AuditLog row per credential-bearing
    dispatch (scan-level audit, NOT per-job per ScanAction policy)."""
    s = web_scan
    credential = ProjectCredential(
        organization_id=s["org"].id,
        project_id=s["project"].id,
        auth_type="cookie",
        encrypted_data=encrypt_credential({"data": "session=audit"}),
    )
    db_session.add(credential)
    await db_session.commit()

    orch = ScanOrchestrator(db_session, fake_redis)
    await orch.dispatch(s["scan"], s["identity"])

    audit_rows = (
        await db_session.execute(
            select(AuditLog).where(
                AuditLog.action == ScanAction.SCAN_CREDENTIAL_DECRYPTED.value,
                AuditLog.resource_id == s["scan"].id,
            )
        )
    ).scalars().all()
    assert len(audit_rows) == 1, "exactly one SCAN_CREDENTIAL_DECRYPTED row per dispatch"
    row = audit_rows[0]
    assert row.details["credential_id"] == str(credential.id)
    assert row.details["credential_auth_type"] == "cookie"
    assert row.actor_id == s["user"].id


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

    # DB rows persisted despite Redis failure. M8.1β.2: FULL_WEB phase-1
    # is recon-only (1 job), so the commit-then-dispatch contract pins 1.
    persisted = (
        await db_session.execute(
            select(ScanJob).where(ScanJob.scan_id == s["scan"].id)
        )
    ).scalars().all()
    assert len(persisted) == 1, (
        f"commit-then-dispatch contract: recon ScanJob row must persist "
        f"even when queue dispatch fails — got {len(persisted)} rows"
    )
    assert persisted[0].engine == "recon"

    # Audit row was emitted as part of the orchestrator's transaction
    # (which committed before the queue.dispatch call).
    from app.models.audit import AuditLog
    audits = (
        await db_session.execute(
            select(AuditLog).where(AuditLog.action == "scan.dispatched")
        )
    ).scalars().all()
    assert len(audits) == 1
    assert audits[0].details["job_count"] == 1


# ============================================================
# M8.1β.1 engine-variant resolution (shieldscan-docs bb3e75f)
# ============================================================
#
# Per ADR-022 addendum continuation (SPEC §13): nuclei_fast in QUICK
# ScanType folds into engine=nuclei + ScanConfig.Depth="quick" via the
# _DEPTH_FOR_SCAN_TYPE map. nuclei_api/zap_api in API ScanType fold to
# engine=nuclei/zap with target.target_type="api" (already auto-set by
# _target_type_for). Y-ENGINE-VARIANT-RESOLUTION (a) config-flag.


@pytest_asyncio.fixture
async def quick_scan(db_session):
    """Persisted QUICK-ScanType scan flow — for M8.1β.1 Depth injection.
    Mirrors web_scan but with scan_type=QUICK + config={} so the
    _DEPTH_FOR_SCAN_TYPE default is observable."""
    org = Organization(name="Q Org", slug=f"q-{uuid4().hex[:8]}")
    db_session.add(org)
    await db_session.flush()
    await use_org(db_session, org.id)

    user = User(
        email=f"q-{uuid4().hex[:6]}@t.co",
        hashed_password=hash_password("QPass-1"),
        full_name="Q",
        email_verified=True,
    )
    db_session.add(user)
    await db_session.flush()
    db_session.add(
        Membership(user_id=user.id, organization_id=org.id, role=MembershipRole.ADMIN)
    )

    project = Project(
        organization_id=org.id,
        name="QApp",
        target_url="https://q.example.com",
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
        config={},  # NO caller-supplied depth — default injection observable
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
        "scan": scan,
        "identity": identity,
    }


async def _seed_attack_surface(db_session, scan, org, url="https://api.q.example.com"):
    """Insert one live AttackSurface row for a scan (recon-discovered)."""
    db_session.add(
        AttackSurface(
            organization_id=org.id,
            scan_id=scan.id,
            root_domain="example.com",
            subdomain=url.split("://", 1)[-1],
            full_url=url,
            status=SubdomainStatus.LIVE,
            status_code=200,
        )
    )
    await db_session.commit()


@pytest.mark.asyncio
async def test_dispatch_quick_phase2_injects_depth_quick_default(
    quick_scan, db_session, fake_redis
):
    """QUICK ScanType injects depth="quick" into the wire config block
    of PHASE-2 tool jobs when caller did NOT supply scan.config["depth"].
    Per M8.1β.1 engine-variant resolution (SPEC §13 ADR-022 continuation)
    composed with M8.1β.2 ADR-028 two-phase dispatch: nuclei depth knob
    flows through _build_config_block at phase-2."""
    s = quick_scan
    orch = ScanOrchestrator(db_session, fake_redis)

    # Phase-1: recon only.
    phase1 = await orch.dispatch(s["scan"], s["identity"])
    assert len(phase1) == 1 and phase1[0].engine == "recon"
    assert await fake_redis.brpop("shieldscan:queue:normal", timeout=1) is not None

    # Seed live target + phase-2 dispatch.
    await _seed_attack_surface(db_session, s["scan"], s["org"])
    phase2 = await orch.dispatch_phase2(scan_id=s["scan"].id)
    # QUICK non-recon tools: (nuclei, sslyze).
    assert len(phase2) == 2

    queued = []
    for _ in range(len(phase2)):
        item = await fake_redis.brpop("shieldscan:queue:normal", timeout=1)
        assert item is not None
        queued.append(json.loads(item[1]))
    for q in queued:
        assert q["config"].get("depth") == "quick", (
            f"engine={q['engine']} phase-2 payload config must carry "
            f"depth='quick' per _DEPTH_FOR_SCAN_TYPE[QUICK]; got "
            f"{q['config']!r}"
        )


@pytest.mark.asyncio
async def test_dispatch_quick_phase2_caller_supplied_depth_wins(
    quick_scan, db_session, fake_redis
):
    """Caller-supplied scan.config["depth"] takes precedence over the
    _DEPTH_FOR_SCAN_TYPE default at phase-2. Operator-tuning preserved."""
    s = quick_scan
    s["scan"].config = {"depth": "deep"}
    await db_session.commit()
    await db_session.refresh(s["scan"])
    s["scan"].project = s["project"]  # type: ignore[attr-defined]

    orch = ScanOrchestrator(db_session, fake_redis)
    phase1 = await orch.dispatch(s["scan"], s["identity"])
    assert len(phase1) == 1 and phase1[0].engine == "recon"
    assert await fake_redis.brpop("shieldscan:queue:normal", timeout=1) is not None

    await _seed_attack_surface(db_session, s["scan"], s["org"])
    phase2 = await orch.dispatch_phase2(scan_id=s["scan"].id)

    queued = []
    for _ in range(len(phase2)):
        item = await fake_redis.brpop("shieldscan:queue:normal", timeout=1)
        assert item is not None
        queued.append(json.loads(item[1]))
    for q in queued:
        assert q["config"].get("depth") == "deep", (
            "caller-supplied depth MUST win over _DEPTH_FOR_SCAN_TYPE "
            "default at phase-2"
        )


# ---------------------------------------------------------------- M8.1β.2 ADR-028 phase-1/phase-2


@pytest.mark.asyncio
async def test_dispatch_non_web_scan_type_preserves_direct_dispatch(
    db_session, fake_redis
):
    """Non-web ScanTypes (CONTAINER) dispatch all SCAN_TYPE_TOOLS engines
    directly at phase-1 (no recon phase) — existing behavior preserved."""
    org = Organization(name="NW Org", slug=f"nw-{uuid4().hex[:8]}")
    db_session.add(org)
    await db_session.flush()
    await use_org(db_session, org.id)
    user = User(
        email=f"nw-{uuid4().hex[:6]}@t.co",
        hashed_password=hash_password("NwPass-1"),
        full_name="NW",
        email_verified=True,
    )
    db_session.add(user)
    await db_session.flush()
    db_session.add(
        Membership(user_id=user.id, organization_id=org.id, role=MembershipRole.ADMIN)
    )
    project = Project(
        organization_id=org.id,
        name="NwApp",
        target_url="https://nw.example.com",
        root_domain="example.com",
        domain_verified=True,
    )
    db_session.add(project)
    await db_session.flush()
    scan = Scan(
        organization_id=org.id,
        project_id=project.id,
        scan_type=ScanType.CONTAINER,
        status=ScanStatus.QUEUED,
        priority="normal",
        config={},
    )
    db_session.add(scan)
    await db_session.commit()
    await db_session.refresh(scan)
    scan.project = project  # type: ignore[attr-defined]
    identity = AuthIdentity(
        kind="jwt", organization_id=org.id, user=user, role=MembershipRole.ADMIN
    )

    orch = ScanOrchestrator(db_session, fake_redis)
    jobs = await orch.dispatch(scan, identity)
    # CONTAINER tuple: (trivy-container, checkov) — no recon job.
    assert sorted(j.engine for j in jobs) == sorted(
        SCAN_TYPE_TOOLS[ScanType.CONTAINER]
    )
    assert "recon" not in {j.engine for j in jobs}


@pytest.mark.asyncio
async def test_dispatch_phase2_creates_per_target_tool_jobs(
    web_scan, db_session, fake_redis
):
    """Phase-2 creates N×M ScanJobs (N live targets × M non-recon tools)
    with the Q2 (a.ii) target_hash idempotency-key format."""
    import hashlib

    s = web_scan
    orch = ScanOrchestrator(db_session, fake_redis)
    await orch.dispatch(s["scan"], s["identity"])  # phase-1 (recon + audit)
    assert await fake_redis.brpop("shieldscan:queue:normal", timeout=1) is not None

    # Two live targets.
    urls = ["https://a.example.com", "https://b.example.com"]
    for u in urls:
        await _seed_attack_surface(db_session, s["scan"], s["org"], url=u)

    phase2 = await orch.dispatch_phase2(scan_id=s["scan"].id)
    non_recon = [t for t in SCAN_TYPE_TOOLS[ScanType.FULL_WEB] if t != "recon"]
    assert len(phase2) == 2 * len(non_recon)

    # Idempotency-key format: {scan_id}:{tool}:{sha256(url)[:16]}:{ts}
    for job in phase2:
        target_hash = hashlib.sha256(job.target_url.encode()).hexdigest()[:16]
        assert f":{target_hash}:" in job.idempotency_key
        assert job.idempotency_key.startswith(f"{s['scan'].id}:{job.engine}:")


@pytest.mark.asyncio
async def test_dispatch_phase2_empty_attack_surface_emits_audit_no_jobs(
    web_scan, db_session, fake_redis
):
    """Empty-AttackSurface (Q2 i): zero phase-2 jobs, but the
    SCAN_DISPATCHED_PHASE2 audit is still emitted (Q5 b.i always-emit)."""
    s = web_scan
    orch = ScanOrchestrator(db_session, fake_redis)
    await orch.dispatch(s["scan"], s["identity"])  # phase-1
    assert await fake_redis.brpop("shieldscan:queue:normal", timeout=1) is not None

    # No AttackSurface rows seeded → empty surface.
    phase2 = await orch.dispatch_phase2(scan_id=s["scan"].id)
    assert phase2 == []

    audits = (
        await db_session.execute(
            select(AuditLog).where(
                AuditLog.action == ScanAction.SCAN_DISPATCHED_PHASE2.value,
                AuditLog.resource_id == s["scan"].id,
            )
        )
    ).scalars().all()
    assert len(audits) == 1
    assert audits[0].details["target_count"] == 0
    assert audits[0].details["job_count"] == 0
    assert audits[0].details["phase"] == "tools"


@pytest.mark.asyncio
async def test_dispatch_phase2_audit_emission_rich_details(
    web_scan, db_session, fake_redis
):
    """SCAN_DISPATCHED_PHASE2 carries rich details + recon_event_id
    pointing at the phase-1 SCAN_DISPATCHED audit (Q5 b + b.i)."""
    s = web_scan
    orch = ScanOrchestrator(db_session, fake_redis)
    await orch.dispatch(s["scan"], s["identity"])
    assert await fake_redis.brpop("shieldscan:queue:normal", timeout=1) is not None

    await _seed_attack_surface(db_session, s["scan"], s["org"])
    await orch.dispatch_phase2(scan_id=s["scan"].id)

    dispatch_audit = (
        await db_session.execute(
            select(AuditLog).where(
                AuditLog.action == ScanAction.SCAN_DISPATCHED.value,
                AuditLog.resource_id == s["scan"].id,
            )
        )
    ).scalar_one()
    phase2_audit = (
        await db_session.execute(
            select(AuditLog).where(
                AuditLog.action == ScanAction.SCAN_DISPATCHED_PHASE2.value,
                AuditLog.resource_id == s["scan"].id,
            )
        )
    ).scalar_one()
    # actor_id recovered via audit-log lookup (Q7.4 V-WD Option α).
    assert phase2_audit.actor_id == dispatch_audit.actor_id
    d = phase2_audit.details
    assert d["target_count"] == 1
    non_recon = [t for t in SCAN_TYPE_TOOLS[ScanType.FULL_WEB] if t != "recon"]
    assert d["tool_count"] == len(non_recon)
    assert d["job_count"] == len(non_recon)
    assert d["recon_event_id"] == str(dispatch_audit.id)


@pytest.mark.asyncio
async def test_dispatch_phase2_no_dispatch_audit_fails_loud(
    web_scan, db_session, fake_redis
):
    """Phase-2 trigger without a phase-1 SCAN_DISPATCHED audit fails
    loud (Q7 c.ii.B): scan marked FAILED + SCAN_FAILED audit emitted."""
    s = web_scan
    orch = ScanOrchestrator(db_session, fake_redis)
    # NOTE: we do NOT call dispatch() — so no SCAN_DISPATCHED audit exists.
    await _seed_attack_surface(db_session, s["scan"], s["org"])

    phase2 = await orch.dispatch_phase2(scan_id=s["scan"].id)
    assert phase2 == []

    fresh = await db_session.get(Scan, s["scan"].id)
    await db_session.refresh(fresh)
    assert fresh.status == ScanStatus.FAILED

    fail_audits = (
        await db_session.execute(
            select(AuditLog).where(
                AuditLog.action == ScanAction.SCAN_FAILED.value,
                AuditLog.resource_id == s["scan"].id,
            )
        )
    ).scalars().all()
    assert len(fail_audits) == 1
    assert fail_audits[0].details["reason"] == "no_dispatch_audit_found"
