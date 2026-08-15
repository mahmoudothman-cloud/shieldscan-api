"""Fail-loud guard: no query against a tenant table without tenant context.

With the null-safe policy predicate, a missing ``app.current_org_id`` yields
zero rows rather than an error. That is the right *safety* posture — a missed
tenant context can never mean "all rows" — but it is a terrible *detectability*
posture for a vulnerability scanner: "0 vulnerabilities found" is a false
negative a customer will act on, whereas a 500 gets investigated. This guard
converts that silence into a loud, distinct failure.

What it checks
--------------
Two independent facts, not one:

  intent   ``session.info[ORG_INTENT_KEY]``    — what the request means to be
  applied  ``connection.info[ORG_APPLIED_KEY]`` — what actually reached the
                                                  connection, written only
                                                  after the statement landed

Requiring both, and requiring them to agree, is what makes the check
un-foolable. A guard trusting ``session.info`` alone was demonstrated to pass a
statement when the intent was recorded but the GUC was never applied — exactly
the silent-empty-result it exists to catch. Validating against the connection
actually in use makes drift fail closed.

Cost
----
The hook fires for every ORM-mediated statement in the process, so it does no
I/O: table identification reads ``ORMExecuteState.all_mappers`` (already
computed for the statement) and both facts are in-memory dicts. There is
deliberately no ``current_setting`` round-trip.

Coverage
--------
``do_orm_execute`` fires for everything routed through ``Session.execute()`` —
ORM selects, and Core ``select()`` / ``update()`` / ``delete()`` — all verified
guarded. It does NOT fire for unit-of-work flush, so statements the flush
generates are covered by other mechanisms:

  =========================== ==================== ===================
  operation                   caught by            behaviour
  =========================== ==================== ===================
  SELECT (any, via execute)   this guard           raises
  Core UPDATE/DELETE          this guard           raises
  INSERT (add + flush)        policy WITH CHECK    raises RLS violation
  UPDATE (mutate + flush)     SQLAlchemy rowcount  raises StaleDataError
  DELETE (delete + flush)     NOTHING              *see below*
  =========================== ==================== ===================

KNOWN SILENT PATH — ORM delete via flush
----------------------------------------
``session.delete(obj)`` followed by ``flush()`` with no tenant context matches
zero rows (the policy's USING clause hides them) and SQLAlchemy emits only a
``SAWarning`` — ``confirm_deleted_rows`` warns, it does not raise. The flush and
commit BOTH SUCCEED. Demonstrated against a real RLS'd table as the app role.

What this is and is not:

  * The row is NOT deleted and no other tenant's data is touched — there is no
    data loss and no cross-tenant effect.
  * The caller is told the delete succeeded when nothing was removed. In an
    API that means a 204 on a resource that still exists.

Reachability today is narrow: obtaining the object requires a load, which is a
guarded SELECT that would already have raised without context; context would
then have to be lost between load and flush, and nothing in the request path
clears ``session.info`` mid-request. It is documented rather than fixed because
closing it needs a ``before_flush`` hook inspecting ``session.deleted``, which
is a behavioural change deserving its own review. If a delete endpoint ever
reports success against a row that still exists, look here first.

Verified separately: nothing in ``src/`` issues statements outside a Session
(no engine-level ``.connect()``/``.begin()``), and no runtime ``text()``
statement names a tenant table — both pinned as invariant tests, so the ORM
path is the whole surface.
"""

from __future__ import annotations

import logging

from sqlalchemy import event
from sqlalchemy.orm import ORMExecuteState

from app.db.policies import TENANT_TABLES
from app.db.tenant_context import ORG_APPLIED_KEY, ORG_INTENT_KEY, TenantSession

logger = logging.getLogger(__name__)

_TENANT_TABLES: frozenset[str] = frozenset(TENANT_TABLES)


class MissingTenantContextError(RuntimeError):
    """A tenant-scoped statement ran without a verified tenant context.

    A distinct type on purpose: it must be greppable and alertable, and must
    never be indistinguishable from a generic failure. Nothing in the request
    path catches it — the only broad ``except Exception`` wrapping a DB write
    is ``dependencies._update_api_key_last_used``, which targets ``api_keys``
    (outside TENANT_TABLES per ADR-012) and carries a note saying so.
    """


def _tenant_tables_for(orm_ctx: ORMExecuteState) -> set[str]:
    """Tenant tables this statement touches. No SQL compilation, no I/O."""
    tables: set[str] = set()
    for mapper in orm_ctx.all_mappers:
        table = mapper.local_table
        name = getattr(table, "name", None)
        if name in _TENANT_TABLES:
            tables.add(name)
    return tables


def _check_tenant_context(orm_ctx: ORMExecuteState) -> None:
    tables = _tenant_tables_for(orm_ctx)
    if not tables:
        return

    session = orm_ctx.session
    intent = session.info.get(ORG_INTENT_KEY)
    applied = session.connection().connection.info.get(ORG_APPLIED_KEY)
    if intent is not None and applied is not None and applied == intent:
        return

    target = ", ".join(sorted(tables))
    # Report WHY, not a bare match flag: with both values absent, "match=True"
    # reads as if the check passed. The three states are distinguishable here
    # so an incident does not start with a misleading log line.
    if intent is None and applied is None:
        reason = "no tenant context was established"
    elif intent is None:
        reason = "the connection carries a context this session never set"
    elif applied is None:
        reason = "the context was recorded but never applied to the connection"
    else:
        reason = "the recorded and applied contexts disagree"
    logger.error(
        "tenant context missing for %s: %s (intent=%s applied=%s). The "
        "statement was blocked; with RLS active it would have returned zero "
        "rows silently.",
        target,
        reason,
        intent,
        applied,
    )
    raise MissingTenantContextError(
        f"query against tenant table(s) {target} without verified tenant "
        f"context (intent={intent!r} applied={applied!r}). Call "
        f"app.db.tenant_context.set_tenant_context(db, org_id) first."
    )


def install_tenant_guard() -> None:
    """Register the guard on TenantSession. Idempotent.

    Registered on ``TenantSession``, never on ``orm.Session``: a listener on
    the base class applies to every session in the process, and the test
    harness builds an engine per test, so global registration leaks handlers
    across tests and can mask the very failure under test.
    """
    if not event.contains(TenantSession, "do_orm_execute", _check_tenant_context):
        event.listen(TenantSession, "do_orm_execute", _check_tenant_context)


def remove_tenant_guard() -> None:
    """Unregister the guard. For tests that assert the un-guarded behaviour."""
    if event.contains(TenantSession, "do_orm_execute", _check_tenant_context):
        event.remove(TenantSession, "do_orm_execute", _check_tenant_context)
