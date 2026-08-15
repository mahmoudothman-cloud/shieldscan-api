"""Async SQLAlchemy engine + session factory.

NOTE: a legacy ``src/app/db.py`` module used to coexist with this
package; Python's import system picked this package over the module,
leaving ``db.py`` unreachable. Consolidated here in the 2.3.4 dep
commit when ``get_db`` first needed ``AsyncSessionLocal``.
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import event
from sqlalchemy.engine import Result
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.config import settings
from app.db.tenant_context import ORG_APPLIED_KEY, TENANT_GUC, TenantSession
from app.db.tenant_guard import install_tenant_guard

engine = create_async_engine(settings.DATABASE_URL, echo=False, future=True)


@event.listens_for(engine.sync_engine, "reset")
def _clear_tenant_context(dbapi_connection, connection_record, reset_state) -> None:
    """Clear the tenant GUC when a connection returns to the pool.

    ``SET app.current_org_id`` is non-LOCAL, so it lives on the connection and
    survives the pool's default ROLLBACK-on-return. Without this, a request that
    commits leaves its org on the connection, and the NEXT request to check that
    connection out inherits it — demonstrated: a second session on the same
    pooled connection read the first session's tenant rows.

    Order is load-bearing. ``SET``/``RESET`` are themselves transactional, so a
    bare RESET is undone by the pool's subsequent ROLLBACK and the context
    leaks anyway. Rolling back FIRST, then resetting, was the only variant clean
    across all three cases tested (clean check-in, check-in with an open
    transaction, and sustained connection churn). ``DISCARD ALL`` also works but
    is far broader — it drops prepared statements, plans and temp state — and it
    raised ActiveSQLTransactionError on one path.

    The applied-marker is cleared here too, in the same breath as the GUC, so
    the marker can never outlive the context it attests to.
    """
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("ROLLBACK")
        cursor.execute(f"RESET {TENANT_GUC}")
    finally:
        cursor.close()
    connection_record.info.pop(ORG_APPLIED_KEY, None)


AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    sync_session_class=TenantSession,
    expire_on_commit=False,
)


# Tenant guard, installed at engine setup so the decision is made once per
# process. The flag governs THIS ONLY — never the after_begin re-apply or the
# reset handler above, whose off-state leaks tenant context between requests.
if settings.TENANT_GUARD_ENABLED:
    install_tenant_guard()
else:
    logging.getLogger(__name__).warning(
        "TENANT_GUARD_ENABLED is false — queries against tenant tables will "
        "NOT be checked for tenant context. A missing context now yields a "
        "SILENT empty result instead of an error. This should only ever be a "
        "temporary incident measure; re-enable it."
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
