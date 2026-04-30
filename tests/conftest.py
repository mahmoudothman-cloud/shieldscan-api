"""Shared test fixtures.

Fixture dependency graph (added across Sub-task 2.3.4):

    db_session            — persistent AsyncConnection bound session with
                            RLS + shieldscan_app role + schema applied.
                            Used by pure-service tests that don't touch
                            FastAPI.

    fake_redis            — fresh fakeredis.aioredis.FakeRedis per test.
                            Used by service tests (rate limiter, email
                            verification, token revocation) and by the
                            `client` fixture (via dep override).

    email_service_stub    — fresh app.services.email.ConsoleEmailService
                            per test; its outbox is inspectable.

    existing_user         — yields (User, plaintext_password). Builds via
                            register_identity so Org + Membership +
                            verification email are all set up.

    auth_headers          — yields {"Authorization": "Bearer <access>"}
                            for the existing_user. Uses create_access_token
                            directly (no round-trip through /auth/login).

    client                — httpx.AsyncClient bound to app.main:app with
                            dep overrides installed for get_db, get_redis,
                            and get_email_service. State shared with
                            db_session, fake_redis, email_service_stub so
                            tests can assert on both sides.

Future test authors: use `client` for endpoint tests, direct fixtures
(db_session + fake_redis) for service tests. `auth_headers` is the
canonical way to make an authenticated request.
"""

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
# A real, valid Fernet key (base64-urlsafe 32 bytes). The previous
# placeholder string was NOT a valid Fernet key and would crash any
# code path that actually instantiated Fernet (Task 3.X surfaced this).
# Stable across test runs so encrypted-blob byte assertions are
# deterministic.
os.environ.setdefault(
    "FERNET_KEY",
    "c2hpZWxkc2Nhbi10ZXN0LWZlcm5ldC1rZXktMzJieSE=",
)

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


# ---------------------------------------------------------------- harness fixtures


@pytest_asyncio.fixture
async def fake_redis():
    """Fresh fakeredis.aioredis.FakeRedis, decode_responses=True to
    match the production client shape (see app/redis_client.py)."""
    from fakeredis import aioredis as fakeredis_aio

    client = fakeredis_aio.FakeRedis(decode_responses=True)
    try:
        yield client
    finally:
        await client.flushall()
        await client.aclose()


@pytest_asyncio.fixture
async def email_service_stub():
    """Fresh ConsoleEmailService per test — outbox starts empty."""
    from app.services.email import ConsoleEmailService, reset_default_service

    reset_default_service()
    yield ConsoleEmailService()
    reset_default_service()


@pytest_asyncio.fixture
async def existing_user(db_session, fake_redis, email_service_stub):
    """Register a user via the orchestrator. Yields (User, plaintext_password)
    — tests need the plaintext to exercise /auth/login."""
    from app.services.identity import register_identity

    password = "TestPass-123-secure"
    user = await register_identity(
        db_session,
        fake_redis,
        email_service_stub,
        email="existing@test.com",
        password=password,
        full_name="Existing User",
        organization_name="Existing Co",
    )
    yield user, password


@pytest_asyncio.fixture
async def auth_headers(existing_user):
    """Bearer headers for an access token minted for `existing_user`.
    Skips /auth/login — use only when the endpoint under test isn't
    login itself."""
    from app.services.auth import create_access_token

    user, _ = existing_user
    token = create_access_token(sub=str(user.id))
    return {"Authorization": f"Bearer {token}"}


@pytest_asyncio.fixture
async def client(db_session, fake_redis, email_service_stub):
    """httpx.AsyncClient bound to app.main:app with get_db / get_redis /
    get_email_service overrides installed. Shares state with the
    db_session, fake_redis, email_service_stub fixtures so assertions
    on both sides of a request see the same data.
    """
    from httpx import ASGITransport, AsyncClient

    from app.dependencies import get_db
    from app.main import app
    from app.redis_client import get_redis
    from app.services.email import get_email_service

    async def _override_db():
        yield db_session

    async def _override_redis():
        yield fake_redis

    def _override_email():
        return email_service_stub

    app.dependency_overrides[get_db] = _override_db
    app.dependency_overrides[get_redis] = _override_redis
    app.dependency_overrides[get_email_service] = _override_email

    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            yield ac
    finally:
        app.dependency_overrides.clear()
