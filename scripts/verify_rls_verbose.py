"""Reproduce test_rls_prevents_cross_tenant_project_access with SQL echo on.

Shows every statement the cross-tenant test emits, so the SET ROLE +
SET app.current_org_id + INSERT + SELECT sequence is auditable by eye.
"""

from __future__ import annotations

import asyncio
import logging
import os
from uuid import uuid4

os.environ.setdefault(
    "DATABASE_URL",
    "postgresql+asyncpg://shieldscan:shieldscan@localhost:5432/shieldscan_test",
)
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("QDRANT_URL", "http://localhost:6333")
for k in (
    "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "STRIPE_SECRET_KEY",
    "STRIPE_WEBHOOK_SECRET", "R2_ACCOUNT_ID", "R2_ACCESS_KEY",
    "R2_SECRET_KEY", "R2_BUCKET", "JWT_SECRET_KEY", "FERNET_KEY",
):
    os.environ.setdefault(k, "x")

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

from app.db.policies import (
    APP_ROLE_NAME,
    app_role_upgrade_sql,
    audit_triggers_upgrade_sql,
    rls_upgrade_sql,
)
from app.models import __init__ as _models  # noqa: F401 register metadata
from app.models.base import Base
from app.models.identity import Organization
from app.models.projects import Project


async def main() -> None:
    # Echo=True prints every SQL statement on the engine; we silence the
    # schema-setup noise and turn it on just for the tenant-switch dance.
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    engine_silent = create_async_engine(os.environ["DATABASE_URL"], echo=False)
    async with engine_silent.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
        for sql in rls_upgrade_sql():
            await conn.execute(text(sql))
        for sql in audit_triggers_upgrade_sql():
            await conn.execute(text(sql))
        for sql in app_role_upgrade_sql():
            await conn.execute(text(sql))
    await engine_silent.dispose()

    # Now the verbose session — this is what the test effectively runs.
    engine = create_async_engine(os.environ["DATABASE_URL"], echo=True)
    connection = await engine.connect()

    print("\n─── 0. SET ROLE to non-superuser app role ───────────────────")
    await connection.execute(text(f"SET ROLE {APP_ROLE_NAME};"))

    print("\n─── 1. Create Org A and Org B (admin bootstrap) ─────────────")
    org_a = Organization(name="Org A", slug="verif-a")
    org_b = Organization(name="Org B", slug="verif-b")
    session = AsyncSession(bind=connection, expire_on_commit=False)
    session.add_all([org_a, org_b])
    await session.flush()

    print("\n─── 2. SET app.current_org_id = <Org A> ─────────────────────")
    await connection.execute(text(f"SET app.current_org_id = '{org_a.id}';"))

    print("\n─── 3. Org A inserts a Project ──────────────────────────────")
    project_a = Project(
        organization_id=org_a.id,
        name="A web",
        target_url="https://a.verif",
        root_domain="a.verif",
    )
    session.add(project_a)
    await session.commit()

    print("\n─── 4. Org A SELECTs projects (should see 1) ────────────────")
    result = await session.execute(select(Project))
    rows = result.scalars().all()
    print(f"   -> Org A sees {len(rows)} project(s)")
    assert len(rows) == 1, "Org A must see its own project"

    print("\n─── 5. Switch GUC: SET app.current_org_id = <Org B> ─────────")
    await connection.execute(text(f"SET app.current_org_id = '{org_b.id}';"))

    print("\n─── 6. Org B SELECTs projects (should see 0 — RLS blocks) ───")
    result = await session.execute(select(Project))
    rows = result.scalars().all()
    print(f"   -> Org B sees {len(rows)} project(s)")
    assert len(rows) == 0, f"Org B saw Org A's project — RLS FAILED (count={len(rows)})"

    print("\n─── 7. Org B targeted-read by Org A's id (should be None) ───")
    r = await connection.execute(
        text("SELECT id FROM projects WHERE id = :id"), {"id": project_a.id}
    )
    row = r.first()
    print(f"   -> targeted read returns: {row}")
    assert row is None, "Org B retrieved Org A's row by id — RLS FAILED"

    print("\n─── 8. Switch back to Org A, confirm still visible ──────────")
    await connection.execute(text(f"SET app.current_org_id = '{org_a.id}';"))
    result = await session.execute(select(Project))
    rows = result.scalars().all()
    print(f"   -> Org A now sees {len(rows)} project(s)")
    assert len(rows) == 1, "Org A lost visibility to its own project"

    await session.close()
    await connection.close()
    await engine.dispose()
    print("\n✓ cross-tenant RLS verified")


if __name__ == "__main__":
    asyncio.run(main())
