"""The single place tenant context is established (RLS `app.current_org_id`).

Every runtime query against a TENANT_TABLES table is scoped by the
`tenant_isolation` policy, which reads the session-local GUC
`app.current_org_id`. This module owns setting it. Nothing else should issue
`SET app.current_org_id` / `set_config('app.current_org_id', ...)` directly —
a Phase-4 test enforces that.

Why one setter
--------------
The GUC used to be set at 14 hand-written call sites across 5 files. Two
properties make that untenable once RLS is actually enforced:

1. ``TenantSession`` re-applies the GUC at the start of every transaction from
   ``session.info``. A call site that issues the SET but forgets to record the
   intent works until the request's first commit, then the context silently
   vanishes — a subtler failure than never setting it at all. One setter that
   writes both makes the pair inseparable.

2. The guard (Phase 3b) distinguishes *intent* (``session.info``) from
   *applied* (``connection.info``, written only after the statement lands) and
   raises when they disagree. Both halves have to be written in lockstep.

Why ``set_config`` rather than ``SET``
--------------------------------------
PostgreSQL does not accept a bind parameter on a bare ``SET``:
``text("SET app.current_org_id = :org")`` raises ProgrammingError, so the old
call sites all interpolated the uuid into the SQL string. They were
UUID-validated, so this was not an injection hole — but it was safe by
convention rather than by construction. ``set_config(name, value, is_local)``
is an ordinary function call and takes a real bind parameter.

``is_local=False`` is deliberate and matches the previous ``SET`` semantics:
the value must outlive the transaction, because request handlers commit and
then keep querying (routes/projects.py commits, then reads
project_credentials in the same request). ``SET LOCAL`` / ``is_local=True``
is cleared at commit and would break those paths.
"""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session as SyncSession

# GUC read by the tenant_isolation policy (see db/policies.py).
TENANT_GUC = "app.current_org_id"

# session.info key: the org this session INTENDS to operate as. Written by
# set_tenant_context, read by the after_begin re-apply below.
ORG_INTENT_KEY = "tenant_org_id"

# connection.info key: the org actually applied to the connection in use,
# written only AFTER the statement lands. Phase 3b's guard requires this to be
# present and to agree with the intent; the pool reset handler in db/__init__
# clears it in the same breath as the GUC so the two cannot drift apart.
ORG_APPLIED_KEY = "tenant_org_applied"

_SET_TENANT_GUC = text(f"SELECT set_config('{TENANT_GUC}', :org_id, false)")


class TenantSession(SyncSession):
    """Sync Session subclass carrying the tenant-context listeners.

    A dedicated subclass, NOT ``orm.Session``: listeners registered on the base
    class apply to every session in the process, including those created by
    other engines. While proving this design out, a globally-registered
    ``after_begin`` from a previous engine kept firing and silently applied the
    GUC for an engine configured not to — masking the exact failure under test.
    The test harness builds an engine per test, so global registration would
    leak handlers across the suite in the same way.
    """


@event.listens_for(TenantSession, "after_begin")
def _reapply_tenant_guc(session: SyncSession, transaction, connection) -> None:
    """Re-apply the session's tenant context at the start of every transaction.

    A non-LOCAL ``SET`` lives on the *connection*, but a Session releases its
    connection back to the pool at every commit and checks out a fresh one for
    the next transaction. Without this, the GUC set at the top of a request is
    gone for every statement after the request's first commit — which the pool
    reset handler then makes permanent by clearing it on check-in.

    Reading from ``session.info`` keeps the context tied to the logical request
    rather than to whichever connection happens to serve it, so no connection
    has to be pinned for the request's lifetime.
    """
    org_id = session.info.get(ORG_INTENT_KEY)
    if org_id is None:
        return
    connection.execute(_SET_TENANT_GUC, {"org_id": str(org_id)})
    # Recorded only after the statement lands, so the marker is evidence the
    # GUC was applied — not merely that someone intended to apply it.
    connection.connection.info[ORG_APPLIED_KEY] = str(org_id)


async def set_tenant_context(db: AsyncSession, org_id: UUID | str) -> None:
    """Establish the RLS tenant context for this session.

    Records the intent on the session AND applies the GUC to the current
    connection. Call this before any query against a tenant-scoped table, and
    before any INSERT whose ``WITH CHECK`` needs the org to match — including
    ``audit_logs`` writes on pre-auth paths.

    Idempotent and safe to call repeatedly; ``require_org_membership`` re-sets
    it per request by design.
    """
    org_str = str(org_id)
    # Intent first: TenantSession.after_begin fires on the statement below and
    # reads this, so ordering makes the first transaction self-applying.
    db.info[ORG_INTENT_KEY] = org_str
    await db.execute(_SET_TENANT_GUC, {"org_id": org_str})
    # Mark applied here too, not only in after_begin. When a transaction is
    # already open (require_org_membership re-sets the context after
    # get_auth_identity has begun one) after_begin does not fire again, so the
    # listener alone would leave the marker stale against the new intent.
    # PoolProxiedConnection.info is the same mapping the listener writes.
    conn = await db.connection()
    raw = await conn.get_raw_connection()
    raw.info[ORG_APPLIED_KEY] = org_str
