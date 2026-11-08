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
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

# Point Settings at the isolated test database BEFORE app.config is imported
# via any model module. Keep other required env vars set so Settings() does
# not raise on unrelated fields when collection imports app.models.
#
# DATABASE_URL is NOT set here — it is derived from the app's own configured
# URL below, so this tracked file holds no credential. See _test_database_url.
#
# REDIS_URL is a stub: every test uses fakeredis, so this must NOT carry the
# real password and nothing should connect with it.
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

TEST_DB_NAME = "shieldscan_test"


def _test_database_url() -> str:
    """OWNER url for the test database — schema DDL, policies, GRANTs.

    Derived from MIGRATION_DATABASE_URL, NOT from DATABASE_URL. Post-cutover
    DATABASE_URL names the non-superuser app role, which cannot drop or create
    tables: deriving DDL from it fails with "must be owner of table". Only
    falls back to DATABASE_URL when the split is unconfigured (pre-cutover),
    where the two are the same owner url anyway.

    No credential is hardcoded in this tracked file — the passwords live only in
    .env (gitignored). The database name is always replaced with
    ``shieldscan_test``, so an exported url can never point a test run at the
    development database.

    Imported here rather than at module top so the stub env vars above are in
    place before Settings() validates.
    """
    from sqlalchemy.engine import make_url

    from app.config import settings

    owner = settings.MIGRATION_DATABASE_URL or settings.DATABASE_URL
    # render_as_string(hide_password=False) — plain str(URL) masks the password
    # as "***", which would produce an unusable URL.
    resolved = (
        make_url(owner).set(database=TEST_DB_NAME).render_as_string(hide_password=False)
    )
    settings.MIGRATION_DATABASE_URL = resolved
    return resolved


TEST_DATABASE_URL = _test_database_url()


def _test_app_database_url() -> str:
    """Test URL for the NON-SUPERUSER app role — how production connects.

    The suite used to reach the enforced path via ``SET ROLE`` from the owner
    connection. That is not what production does, and the divergence is exactly
    what let the original gap survive: the fixture exercised RLS while the app
    served every request as a superuser that bypassed it. Connecting the test
    sessions as ``shieldscan_app`` removes the divergence.

    Derived independently of DATABASE_URL so it is stable across the cutover —
    before the flip DATABASE_URL names the owner, after it names the app role,
    and this must name the app role either way.
    """
    from sqlalchemy.engine import make_url

    from app.config import settings

    if not settings.APP_DB_PASSWORD:
        raise RuntimeError(
            "APP_DB_PASSWORD is not set. The suite connects as the app role so "
            "it exercises the same path production does; set it in .env "
            "(and ALTER ROLE shieldscan_app WITH PASSWORD to match)."
        )
    resolved = (
        make_url(TEST_DATABASE_URL)
        .set(
            username=settings.APP_DB_USER,
            password=settings.APP_DB_PASSWORD,
            database=TEST_DB_NAME,
        )
        .render_as_string(hide_password=False)
    )
    # app.db builds its engine from settings.DATABASE_URL at import time, and
    # AsyncSessionLocal must reach the TEST database as the APP role — the same
    # identity production uses. Set before any model module loads.
    settings.DATABASE_URL = resolved
    os.environ["DATABASE_URL"] = resolved
    return resolved


TEST_APP_DATABASE_URL = _test_app_database_url()


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
        app_role_upgrade_sql,
        audit_triggers_upgrade_sql,
        rls_upgrade_sql,
    )

    from app.db.tenant_context import TenantSession
    from app.db.tenant_guard import install_tenant_guard

    # The guard is active for the whole suite: a converted call site that
    # writes the SET but not the session intent must fail HERE, not in prod.
    install_tenant_guard()

    # Schema + policies + grants run as the OWNER (DDL, CREATE ROLE).
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

    # The session is still bound to one connection so a test's GUC survives its
    # commits. Production does NOT pin a connection — TenantSession.after_begin
    # re-applies the context per transaction instead — but pinning here keeps
    # the fixture simple and does not change what the guard verifies.
    await engine.dispose()

    # Sessions connect AS the app role — no SET ROLE. Production connects this
    # way, so the suite now takes the same path rather than simulating it.
    # TenantSession carries the after_begin re-apply and the guard.
    app_engine = create_async_engine(TEST_APP_DATABASE_URL, echo=False, future=True)
    connection = await app_engine.connect()
    session = AsyncSession(
        bind=connection,
        sync_session_class=TenantSession,
        expire_on_commit=False,
    )
    try:
        yield session
    finally:
        # Let the request path's fire-and-forget tasks (api_keys.last_used_at)
        # finish on THIS loop before it closes; otherwise a half-run statement
        # keeps a lock that the next test's drop_all waits on forever.
        from app.dependencies import drain_background_tasks

        await drain_background_tasks()
        await session.close()
        await connection.close()
        # app.db.engine is module-level and outlives this test's event loop;
        # asyncpg connections are bound to the loop that created them, so a
        # pooled connection reused on a later loop never reads its socket and
        # a background UPDATE on it blocks the next drop_all forever. Discard
        # the pool (without closing on a foreign loop) so each test's first
        # use creates connections on its own loop.
        from app.db import engine as _app_db_engine

        await _app_db_engine.dispose(close=False)
    await app_engine.dispose()


async def use_org(session: AsyncSession, org_id: UUID | str) -> None:
    """Set the session-local tenant for RLS checks.

    Every test that touches a tenant-scoped table MUST call this after creating
    (and flushing) its Organization — otherwise the policy's WITH CHECK rejects
    the insert, and the tenant guard rejects the read.

    Delegates to the production setter so the harness cannot drift from it: it
    records the session intent AND applies the GUC, which is exactly the pairing
    the guard verifies.
    """
    from app.db.tenant_context import set_tenant_context

    await set_tenant_context(session, org_id)


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
async def session_factory(db_session):
    """A session factory bound to the SAME connection as the test's
    ``db_session`` fixture, so background-task consumers (CompletionsConsumer,
    AIPipelineConsumer) can open fresh per-message sessions on the per-test
    event loop with SET ROLE + SET app.current_org_id + committed visibility
    all lined up. Production uses the global ``AsyncSessionLocal``.

    Shared here for any consumer test; ``test_completions_consumer.py`` keeps
    its own identical local copy (a local fixture overrides this one there).
    """
    from sqlalchemy.ext.asyncio import AsyncSession as _S

    from app.db.tenant_context import TenantSession as _TenantSession

    connection = db_session.bind  # AsyncConnection (test owns lifecycle)

    class _Factory:
        async def __aenter__(self):
            # TenantSession, not a bare AsyncSession: the consumers are 8 of
            # the 13 converted call sites, and a plain session would bypass
            # both the after_begin re-apply and the tenant guard — hollowing
            # out the pre-flight for exactly the code it needs to prove.
            self._session = _S(
                bind=connection,
                sync_session_class=_TenantSession,
                expire_on_commit=False,
            )
            return self._session

        async def __aexit__(self, *exc):
            await self._session.close()
            # Don't close the connection — db_session owns it.

    def _factory():
        return _Factory()

    return _factory


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
