"""Async SQLAlchemy engine + session factory.

NOTE: a legacy ``src/app/db.py`` module used to coexist with this
package; Python's import system picked this package over the module,
leaving ``db.py`` unreachable. Consolidated here in the 2.3.4 dep
commit when ``get_db`` first needed ``AsyncSessionLocal``.
"""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.config import settings

engine = create_async_engine(settings.DATABASE_URL, echo=False, future=True)

AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)
