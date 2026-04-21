from __future__ import annotations

import os
from collections.abc import AsyncGenerator

import pytest_asyncio
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
    engine = create_async_engine(TEST_DATABASE_URL, echo=False, future=True)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )
    async with session_factory() as session:
        try:
            yield session
        finally:
            await session.close()
    await engine.dispose()
