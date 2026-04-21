from __future__ import annotations

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.identity import Organization, User
from app.models.audit import AuditLog
from app.models.projects import Project
from app.models.scans import Scan, ScanStatus, ScanType
from tests.conftest import use_org


# ─── Audit-log append-only trigger tests ────────────────────────────────


async def test_audit_log_update_raises_exception(db_session: AsyncSession) -> None:
    org = Organization(name="AO", slug="ao")
    user = User(email="a@ao.test", hashed_password="x", full_name="A")
    db_session.add_all([org, user])
    await db_session.flush()
    await use_org(db_session, org.id)

    log = AuditLog(
        organization_id=org.id,
        actor_id=user.id,
        action="user.login",
        resource_type="user",
        resource_id=user.id,
    )
    db_session.add(log)
    await db_session.commit()

    # Trigger enforces append-only: UPDATE must raise at the DB layer.
    with pytest.raises(DBAPIError) as excinfo:
        await db_session.execute(
            text("UPDATE audit_logs SET action = 'tampered' WHERE id = :id"),
            {"id": log.id},
        )
        await db_session.commit()
    assert "audit_logs is append-only" in str(excinfo.value)
    await db_session.rollback()


async def test_audit_log_delete_raises_exception(db_session: AsyncSession) -> None:
    org = Organization(name="AD", slug="ad")
    user = User(email="a@ad.test", hashed_password="x", full_name="A")
    db_session.add_all([org, user])
    await db_session.flush()
    await use_org(db_session, org.id)

    log = AuditLog(
        organization_id=org.id,
        actor_id=user.id,
        action="user.login",
        resource_type="user",
        resource_id=user.id,
    )
    db_session.add(log)
    await db_session.commit()

    with pytest.raises(DBAPIError) as excinfo:
        await db_session.execute(
            text("DELETE FROM audit_logs WHERE id = :id"), {"id": log.id}
        )
        await db_session.commit()
    assert "audit_logs is append-only" in str(excinfo.value)
    await db_session.rollback()


# ─── Cross-tenant RLS isolation tests ───────────────────────────────────


async def test_rls_prevents_cross_tenant_project_access(
    db_session: AsyncSession,
) -> None:
    # Two orgs, one project in Org A.
    org_a = Organization(name="Org A", slug="org-a")
    org_b = Organization(name="Org B", slug="org-b")
    db_session.add_all([org_a, org_b])
    await db_session.flush()

    # Act as Org A and insert a project.
    await use_org(db_session, org_a.id)
    project_a = Project(
        organization_id=org_a.id,
        name="A Web",
        target_url="https://a.test",
        root_domain="a.test",
    )
    db_session.add(project_a)
    await db_session.commit()
    project_a_id = project_a.id

    # Org A sees its own project.
    own = (await db_session.execute(select(Project))).scalars().all()
    assert [p.id for p in own] == [project_a_id]

    # Switch to Org B — Org A's project must be invisible.
    await use_org(db_session, org_b.id)
    visible_to_b = (await db_session.execute(select(Project))).scalars().all()
    assert visible_to_b == [], (
        "Org B saw Org A's project — RLS tenant_isolation policy failed"
    )

    # And Org B can't read-by-id either (RLS hides it even from a targeted query).
    row = await db_session.execute(
        text("SELECT id FROM projects WHERE id = :id"), {"id": project_a_id}
    )
    assert row.first() is None

    # Switch back to Org A — it still sees its project.
    await use_org(db_session, org_a.id)
    still_visible = (await db_session.execute(select(Project))).scalars().all()
    assert [p.id for p in still_visible] == [project_a_id]


async def test_rls_prevents_cross_tenant_scan_access(
    db_session: AsyncSession,
) -> None:
    # Two orgs, one scan each — FK-cascade table on projects.
    org_a = Organization(name="Scan A", slug="scan-a")
    org_b = Organization(name="Scan B", slug="scan-b")
    db_session.add_all([org_a, org_b])
    await db_session.flush()

    await use_org(db_session, org_a.id)
    project_a = Project(
        organization_id=org_a.id,
        name="A",
        target_url="https://a.test",
        root_domain="a.test",
    )
    db_session.add(project_a)
    await db_session.flush()
    scan_a = Scan(
        organization_id=org_a.id,
        project_id=project_a.id,
        scan_type=ScanType.FULL_WEB,
        status=ScanStatus.RUNNING,
    )
    db_session.add(scan_a)
    await db_session.commit()
    scan_a_id = scan_a.id

    await use_org(db_session, org_b.id)
    project_b = Project(
        organization_id=org_b.id,
        name="B",
        target_url="https://b.test",
        root_domain="b.test",
    )
    db_session.add(project_b)
    await db_session.flush()
    scan_b = Scan(
        organization_id=org_b.id,
        project_id=project_b.id,
        scan_type=ScanType.FULL_WEB,
        status=ScanStatus.RUNNING,
    )
    db_session.add(scan_b)
    await db_session.commit()
    scan_b_id = scan_b.id

    # As Org B, list scans → only Org B's scan shows up.
    visible_to_b = (await db_session.execute(select(Scan))).scalars().all()
    assert {s.id for s in visible_to_b} == {scan_b_id}
    assert scan_a_id not in {s.id for s in visible_to_b}

    # Flip back to Org A — only Org A's scan shows up.
    await use_org(db_session, org_a.id)
    visible_to_a = (await db_session.execute(select(Scan))).scalars().all()
    assert {s.id for s in visible_to_a} == {scan_a_id}


async def test_rls_with_check_blocks_forged_org_id_insert(
    db_session: AsyncSession,
) -> None:
    # Acting as Org A, we must not be able to insert a row that claims to
    # belong to Org B — WITH CHECK guards this.
    org_a = Organization(name="A", slug="forge-a")
    org_b = Organization(name="B", slug="forge-b")
    db_session.add_all([org_a, org_b])
    await db_session.flush()

    await use_org(db_session, org_a.id)
    forged = Project(
        organization_id=org_b.id,  # <-- forged
        name="Forged",
        target_url="https://forged.test",
        root_domain="forged.test",
    )
    db_session.add(forged)
    with pytest.raises(DBAPIError):
        await db_session.commit()
    await db_session.rollback()
