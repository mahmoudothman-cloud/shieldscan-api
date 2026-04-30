"""Async SQLAlchemy engine + session factory.

NOTE: a legacy ``src/app/db.py`` module used to coexist with this
package; Python's import system picked this package over the module,
leaving ``db.py`` unreachable. Consolidated here in the 2.3.4 dep
commit when ``get_db`` first needed ``AsyncSessionLocal``.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.engine import Result
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.config import settings

engine = create_async_engine(settings.DATABASE_URL, echo=False, future=True)

AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


async def select_fresh(db: AsyncSession, stmt: Any) -> Result[Any]:
    """SELECT with identity-map cache bypass for post-write reads.

    Use when reading a row your transaction just wrote or updated
    (UPSERT, UPDATE, INSERT-then-SELECT). Without this, SQLAlchemy's
    session identity map can return a stale ORM object from cache
    instead of fresh DB state.

    Why we hit this:
      ``AsyncSessionLocal`` is configured with
      ``expire_on_commit=False`` so the session-local
      ``app.current_org_id`` GUC survives commits (RLS depends on it).
      The trade-off: cached ORM objects also survive commits — a
      subsequent SELECT on the same session for the same row returns
      the cached snapshot, not the freshly-written state.

    Why ``populate_existing=True`` is the right tool:
      It instructs SQLAlchemy to re-hydrate the ORM object from the
      SELECT result rather than honoring the identity-map entry.
      Bypasses the cache for THIS query without affecting unrelated
      cached rows.

    Why not ``session.expire_all()``: raises ``MissingGreenlet`` in
    async context (it triggers IO outside a greenlet boundary).

    Why not ``RETURNING`` on the upsert: the ORM still hands back the
    cached object for a row whose primary key already lives in the
    identity map.

    See ``DEVELOPMENT-PATTERNS.md`` (shieldscan-docs) for the full
    pattern. First discovered: Task 3.X PATCH /credentials.
    """
    return await db.execute(stmt, execution_options={"populate_existing": True})
