from __future__ import annotations

import pytest
from sqlalchemy import inspect
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.identity import Organization, User
from app.models.mobile import MobilePlatform, MobileUpload
from app.models.projects import Project, ProjectCredential
from app.models.recon import AttackSurface, SubdomainStatus
from app.models.scans import Scan, ScanJob, ScanStatus, ScanType
from tests.conftest import use_org


# ─── Structural tests: ScanType enum (audit D) ──────────────────────────


def test_scan_type_has_eight_values_including_public() -> None:
    values = {v.value for v in ScanType}
    assert values == {
        "quick",
        "full_web",
        "full_web_source",
        "api",
        "mobile",
        "container",
        "full_spectrum",
        "public",
    }


def test_scan_status_includes_reconning_and_analyzing() -> None:
    values = {v.value for v in ScanStatus}
    # Spec §4.2 + plan: queued, reconning, running, analyzing,
    # completed, partial, failed, canceled
    for name in (
        "queued",
        "reconning",
        "running",
        "analyzing",
        "completed",
        "partial",
        "failed",
        "canceled",
    ):
        assert name in values


# ─── Structural tests: addendum columns on Scan (audit D) ──────────────


def test_scan_has_is_public_column_defaulting_false() -> None:
    col = inspect(Scan).columns["is_public"]
    assert col.nullable is False
    assert col.default is not None
    assert col.default.arg is False


def test_scan_has_public_slug_column_nullable() -> None:
    col = inspect(Scan).columns["public_slug"]
    assert col.nullable is True


def test_scan_has_is_demo_column_defaulting_false() -> None:
    col = inspect(Scan).columns["is_demo"]
    assert col.nullable is False
    assert col.default is not None
    assert col.default.arg is False


def test_scan_job_has_unique_idempotency_key() -> None:
    col = inspect(ScanJob).columns["idempotency_key"]
    assert col.unique is True
    assert col.nullable is False


# ─── Structural tests: Recon (AttackSurface) ────────────────────────────


def test_attack_surface_has_unique_scan_subdomain_constraint() -> None:
    constraints = {c.name for c in inspect(AttackSurface).mapper.local_table.constraints}
    assert "uq_scan_subdomain" in constraints


def test_subdomain_status_values() -> None:
    assert {v.value for v in SubdomainStatus} == {"live", "dead", "timeout"}


def test_mobile_platform_values() -> None:
    assert {v.value for v in MobilePlatform} == {"android", "ios", "unknown"}


# ─── Helpers ────────────────────────────────────────────────────────────


async def _make_org(db: AsyncSession, slug: str = "acme") -> Organization:
    org = Organization(name="Acme", slug=slug)
    db.add(org)
    await db.flush()
    # Every test that writes to tenant-scoped tables must set the RLS
    # tenant context. Doing it in the helper means every caller gets it.
    await use_org(db, org.id)
    return org


async def _make_user(db: AsyncSession, email: str = "u@acme.test") -> User:
    user = User(email=email, hashed_password="x", full_name="U")
    db.add(user)
    await db.flush()
    return user


async def _make_project(db: AsyncSession, org: Organization) -> Project:
    project = Project(
        organization_id=org.id,
        name="Acme Web",
        target_url="https://acme.test",
        root_domain="acme.test",
    )
    db.add(project)
    await db.flush()
    return project


# ─── CRUD tests from the plan ───────────────────────────────────────────


async def test_create_project_and_credential(db_session: AsyncSession) -> None:
    org = await _make_org(db_session)
    project = await _make_project(db_session, org)
    assert project.id is not None
    assert project.domain_verified is False
    assert project.verification_token  # auto-generated hex

    cred = ProjectCredential(
        organization_id=org.id,
        project_id=project.id,
        auth_type="cookie",
        encrypted_data=b"ciphertext-bytes",
    )
    db_session.add(cred)
    await db_session.commit()
    assert cred.id is not None


async def test_create_mobile_scan(db_session: AsyncSession) -> None:
    org = await _make_org(db_session)
    user = await _make_user(db_session)
    project = await _make_project(db_session, org)

    upload = MobileUpload(
        organization_id=org.id,
        project_id=project.id,
        uploaded_by=user.id,
        filename="myapp.apk",
        file_extension=".apk",
        file_size_bytes=18_000_000,
        platform=MobilePlatform.ANDROID,
        r2_key=f"mobile/{org.id}/{project.id}/abc.apk",
    )
    db_session.add(upload)
    await db_session.flush()

    scan = Scan(
        organization_id=org.id,
        project_id=project.id,
        scan_type=ScanType.MOBILE,
        mobile_upload_id=upload.id,
        status=ScanStatus.QUEUED,
    )
    db_session.add(scan)
    await db_session.commit()
    await db_session.refresh(scan)

    assert scan.scan_type == ScanType.MOBILE
    assert scan.is_public is False
    assert scan.is_demo is False
    assert scan.public_slug is None
    assert scan.recon_enabled is True
    assert scan.subdomain_limit == 100


async def test_scan_addendum_fields_can_be_set(db_session: AsyncSession) -> None:
    org = await _make_org(db_session, slug="pub")
    project = await _make_project(db_session, org)

    scan = Scan(
        organization_id=org.id,
        project_id=project.id,
        scan_type=ScanType.PUBLIC,
        is_public=True,
        public_slug="X7K2mQ",
        is_demo=False,
    )
    db_session.add(scan)
    await db_session.commit()
    await db_session.refresh(scan)
    assert scan.is_public is True
    assert scan.public_slug == "X7K2mQ"
    assert scan.scan_type == ScanType.PUBLIC


async def test_attack_surface_insert_and_unique_constraint(
    db_session: AsyncSession,
) -> None:
    org = await _make_org(db_session)
    project = await _make_project(db_session, org)
    scan = Scan(
        organization_id=org.id,
        project_id=project.id,
        scan_type=ScanType.FULL_WEB,
        status=ScanStatus.RUNNING,
    )
    db_session.add(scan)
    await db_session.flush()

    a1 = AttackSurface(
        organization_id=org.id,
        scan_id=scan.id,
        root_domain="acme.test",
        subdomain="api.acme.test",
        full_url="https://api.acme.test",
        status=SubdomainStatus.LIVE,
    )
    db_session.add(a1)
    await db_session.commit()
    assert a1.id is not None

    # Duplicate (same scan_id + subdomain) must violate uq_scan_subdomain
    dup = AttackSurface(
        organization_id=org.id,
        scan_id=scan.id,
        root_domain="acme.test",
        subdomain="api.acme.test",
        full_url="https://api.acme.test",
        status=SubdomainStatus.LIVE,
    )
    db_session.add(dup)
    with pytest.raises(IntegrityError):
        await db_session.commit()
    await db_session.rollback()


async def test_scan_job_idempotency_key_enforced(db_session: AsyncSession) -> None:
    org = await _make_org(db_session)
    project = await _make_project(db_session, org)
    scan = Scan(
        organization_id=org.id,
        project_id=project.id,
        scan_type=ScanType.FULL_WEB,
        status=ScanStatus.RUNNING,
    )
    db_session.add(scan)
    await db_session.flush()

    key = f"{scan.id}:nuclei:1711720200"
    db_session.add(
        ScanJob(
            organization_id=org.id,
            scan_id=scan.id,
            engine="nuclei",
            target_url="https://acme.test",
            status="queued",
            idempotency_key=key,
        )
    )
    await db_session.commit()

    # Second job with same key must be rejected
    db_session.add(
        ScanJob(
            organization_id=org.id,
            scan_id=scan.id,
            engine="nuclei",
            target_url="https://acme.test",
            status="queued",
            idempotency_key=key,
        )
    )
    with pytest.raises(IntegrityError):
        await db_session.commit()
    await db_session.rollback()
