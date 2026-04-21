from __future__ import annotations

import os
from collections.abc import AsyncGenerator
from uuid import UUID

import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

# Point Settings at the isolated test database BEFORE app.config is imported
# via any model module. Keep other required env vars set so Settings() does
# not raise on unrelated fields when collection imports app.models.
os.environ.setdefault(
    "DATABASE_URL",
    "postgresql+asyncpg://shieldscan:shieldscan@localhost:5432/shieldscan_test",
)
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("QDRANT_URL", "http://localhost:6333")
os.environ.setdefault("ANTHROPIC_API_KEY", "test-anthropic")
os.environ.setdefault("OPENAI_API_KEY", "test-openai")
os.environ.setdefault("STRIPE_SECRET_KEY", "sk_test_dummy")
os.environ.setdefault("STRIPE_WEBHOOK_SECRET", "whsec_dummy")
os.environ.setdefault("R2_ACCOUNT_ID", "dummy")
os.environ.setdefault("R2_ACCESS_KEY", "dummy")
os.environ.setdefault("R2_SECRET_KEY", "dummy")
os.environ.setdefault("R2_BUCKET", "shieldscan-test")
os.environ.setdefault("JWT_SECRET_KEY", "test-jwt-secret-key-at-least-32-bytes-xxxxxxx")
os.environ.setdefault("FERNET_KEY", "test-fernet-key-base64-urlsafe-44-bytes=")

TEST_DATABASE_URL = os.environ["DATABASE_URL"]


@pytest_asyncio.fixture
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    # Import here so environment overrides above take effect before model
    # modules pull in app.config.
    from app.models import base as _base  # noqa: F401
    from app.models import identity as _identity  # noqa: F401
    from app.models.base import Base

    # Function-scoped engine. pytest-asyncio 0.24 runs each async test on a
    # fresh event loop, so engines/connections must not outlive a single
    # test — otherwise asyncpg raises "attached to a different loop". The
    # schema is small (handful of tables); create_all/drop_all per test is
    # cheap and avoids cross-test state leakage.
    from app.db.policies import (
        APP_ROLE_NAME,
        app_role_upgrade_sql,
        audit_triggers_upgrade_sql,
        rls_upgrade_sql,
    )

    engine = create_async_engine(TEST_DATABASE_URL, echo=False, future=True)
    async with engine.begin() as conn:
        # drop_all cascades to drop each table's triggers + policies, so
        # no explicit trigger/policy DROP is needed here.
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
        for sql in rls_upgrade_sql():
            await conn.execute(text(sql))
        for sql in audit_triggers_upgrade_sql():
            await conn.execute(text(sql))
        for sql in app_role_upgrade_sql():
            await conn.execute(text(sql))

    # Bind the AsyncSession to a single persistent connection (not the
    # engine directly). Two reasons:
    #   1. A session-level `SET app.current_org_id` must survive commits,
    #      which only happens if the session holds the same connection
    #      across transactions.
    #   2. We `SET ROLE shieldscan_app` on this connection so RLS actually
    #      applies. The owner role (`shieldscan`, POSTGRES_USER) is a
    #      superuser and therefore bypasses RLS unconditionally — FORCE RLS
    #      does NOT override that. Running as a non-superuser role is the
    #      only way to make policies apply in tests.
    connection = await engine.connect()
    await connection.execute(text(f"SET ROLE {APP_ROLE_NAME};"))
    session = AsyncSession(bind=connection, expire_on_commit=False)
    try:
        yield session
    finally:
        await session.close()
        await connection.close()
    await engine.dispose()


async def use_org(session: AsyncSession, org_id: UUID | str) -> None:
    """Set the session-local tenant for RLS checks.

    Every test that writes to a tenant-scoped table MUST call this after
    creating (and flushing) its Organization — otherwise RLS's
    `WITH CHECK (organization_id = current_setting('app.current_org_id'))`
    rejects the insert.
    """
    # Use SET (session-level), not SET LOCAL, so it survives test-level
    # session.commit() calls. Each test gets a fresh connection+engine, so
    # no cross-test leakage.
    await session.execute(text(f"SET app.current_org_id = '{org_id}'"))
