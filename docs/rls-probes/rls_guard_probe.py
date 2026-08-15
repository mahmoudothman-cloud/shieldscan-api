"""Probe 6: two "are we fooling ourselves" checks before Phase 3.

(1) Event 4 disambiguation. The previous probe's "_fail_scan nested session
    sees 4 org-A rows" is only a pass if that session set its OWN GUC. Run the
    nested pattern BOTH ways and show which explains the result.

(2) Guard drift. The guard trusts session.info. Construct the drift case —
    session.info populated but after_begin failing to apply the GUC — and show
    whether a session.info-based guard passes a statement it shouldn't. Then
    show a structure where drift fails CLOSED.
"""

from __future__ import annotations

import asyncio
import uuid
from pathlib import Path

from sqlalchemy import event, text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import Session as SyncSession

ENV = Path("/home/mahmoud/workspace/shieldscan-api/.env")
ROLE = "rls_probe_login"
PW = "probeonlyhex" + uuid.uuid4().hex
ORG_A = str(uuid.uuid4())
OK, BAD = "✅", "❌"
NULLIF = "NULLIF(current_setting('app.current_org_id', true), '')::uuid"

ORG_INTENT = "current_org_id"      # written by the setter helper (intent)
ORG_APPLIED = "org_applied"        # written by after_begin AFTER the SET lands
TENANT_TABLES = ("probe_guard",)


class MissingTenantContext(Exception):
    pass


def owner_url() -> str:
    raw = next(
        ln.split("=", 1)[1].strip()
        for ln in ENV.read_text().splitlines()
        if ln.startswith("DATABASE_URL=")
    )
    return make_url(raw).set(database="shieldscan_test").render_as_string(
        hide_password=False
    )


async def setup(base: str) -> None:
    eng = create_async_engine(base, isolation_level="AUTOCOMMIT")
    async with eng.connect() as c:
        await c.execute(text("DROP TABLE IF EXISTS probe_guard"))
        await c.execute(
            text(
                "CREATE TABLE probe_guard (id serial PRIMARY KEY, "
                "organization_id uuid NOT NULL, label text)"
            )
        )
        await c.execute(text("ALTER TABLE probe_guard ENABLE ROW LEVEL SECURITY"))
        await c.execute(text("ALTER TABLE probe_guard FORCE ROW LEVEL SECURITY"))
        await c.execute(
            text(
                f"CREATE POLICY tenant_isolation ON probe_guard "
                f"USING (organization_id = {NULLIF}) "
                f"WITH CHECK (organization_id = {NULLIF})"
            )
        )
        await c.execute(
            text("INSERT INTO probe_guard (organization_id, label) "
                 "VALUES (:a,'A-1'), (:a,'A-2')"),
            {"a": ORG_A},
        )
        await c.execute(text(f"DROP ROLE IF EXISTS {ROLE}"))
        await c.execute(
            text(f"CREATE ROLE {ROLE} LOGIN PASSWORD '{PW}' "
                 "NOSUPERUSER NOBYPASSRLS NOINHERIT")
        )
        await c.execute(text(f"GRANT USAGE ON SCHEMA public TO {ROLE}"))
        await c.execute(
            text(f"GRANT SELECT, INSERT, UPDATE, DELETE ON probe_guard TO {ROLE}")
        )
        await c.execute(
            text(f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {ROLE}")
        )
    await eng.dispose()


async def teardown(base: str) -> None:
    eng = create_async_engine(base, isolation_level="AUTOCOMMIT")
    async with eng.connect() as c:
        await c.execute(text("DROP TABLE IF EXISTS probe_guard"))
        await c.execute(text(f"REVOKE ALL ON SCHEMA public FROM {ROLE}"))
        await c.execute(text(f"DROP ROLE IF EXISTS {ROLE}"))
    await eng.dispose()


def build(purl: str, *, apply_guc: bool, guard: str | None):
    """apply_guc=False simulates after_begin failing to apply (the drift case).

    Listeners are bound to a DEDICATED sync session class. Registering on the
    global orm.Session leaks handlers across engines — an earlier engine's
    after_begin keeps firing and silently applies the GUC, which masked the
    drift case on the first run of this probe.
    """
    eng = create_async_engine(purl, pool_size=1, max_overflow=0)

    class _ScopedSession(SyncSession):
        pass

    @event.listens_for(eng.sync_engine, "reset")
    def _reset(dbapi_connection, connection_record, reset_state):  # noqa: ANN001
        cur = dbapi_connection.cursor()
        try:
            cur.execute("ROLLBACK")
            cur.execute("RESET app.current_org_id")
        finally:
            cur.close()
        # The applied-marker is cleared with the GUC, so they cannot drift
        # apart at check-in.
        connection_record.info.pop(ORG_APPLIED, None)

    @event.listens_for(_ScopedSession, "after_begin")
    def _after_begin(session, transaction, connection):  # noqa: ANN001
        org = session.info.get(ORG_INTENT)
        if org is None:
            return
        if apply_guc:
            connection.exec_driver_sql(f"SET app.current_org_id = '{org}'")
            # Recorded ONLY after the SET actually lands.
            connection.connection.info[ORG_APPLIED] = org

    if guard is not None:

        @event.listens_for(_ScopedSession, "do_orm_execute")
        def _guard(orm_ctx):  # noqa: ANN001
            sql = str(orm_ctx.statement).lower()
            if not any(t in sql for t in TENANT_TABLES):
                return
            sess = orm_ctx.session
            if guard == "info":
                # v1: trust session.info (the intent).
                if sess.info.get(ORG_INTENT) is None:
                    raise MissingTenantContext("no tenant context (session.info)")
            else:
                # v2: require the APPLIED marker on the connection actually in
                # use, and require it to agree with the intent.
                intent = sess.info.get(ORG_INTENT)
                applied = sess.connection().connection.info.get(ORG_APPLIED)
                if intent is None or applied is None or applied != intent:
                    raise MissingTenantContext(
                        f"tenant context not applied (intent={bool(intent)} "
                        f"applied={bool(applied)} match={applied == intent})"
                    )

    return eng, _ScopedSession


async def set_org(db: AsyncSession, org: str) -> None:
    """The single setter helper: writes session.info AND issues the SET."""
    db.info[ORG_INTENT] = org
    await db.execute(text(f"SET app.current_org_id = '{org}'"))


async def count(db: AsyncSession) -> int:
    from sqlalchemy import select
    from sqlalchemy.orm import declarative_base  # noqa: F401
    # Core select through the ORM path so do_orm_execute fires.
    return (await db.execute(text("SELECT count(*) FROM probe_guard"))).scalar()


async def part1(purl: str) -> None:
    print("=== 8. Event 4 disambiguation: does _fail_scan set its own GUC, or "
          "inherit? ===")
    eng, S = build(purl, apply_guc=True, guard=None)
    f = async_sessionmaker(eng, class_=AsyncSession, sync_session_class=S,
                           expire_on_commit=False)

    # First session establishes org A then "crashes" (session closes).
    async with f() as db:
        await set_org(db, ORG_A)
        await count(db)

    print("  (a) nested session that DOES set its own GUC (the real _fail_scan):")
    async with f() as fail_db:
        await set_org(fail_db, ORG_A)
        n = await count(fail_db)
        await fail_db.commit()
        print(f"      sees {n} row(s)  {OK if n == 2 else BAD}")

    async with f() as db:
        await set_org(db, ORG_A)
        await count(db)

    print("  (b) SAME nested pattern with the SET removed (would it inherit?):")
    async with f() as fail_db:
        guc = (
            await fail_db.execute(
                text("SELECT current_setting('app.current_org_id', true)")
            )
        ).scalar()
        n = await count(fail_db)
        print(f"      inherited GUC={guc!r}, sees {n} row(s)")
        if n == 0:
            print(f"      {OK} (a) passed because it SET its own context, not "
                  "because it inherited one.")
        else:
            print(f"      {BAD} the earlier pass was inheritance — the leak "
                  "with a success label.")
    await eng.dispose()


async def part2(purl: str) -> None:
    print("\n=== 9. Can the guard be fooled by session.info / GUC drift? ===")
    for guard in ("info", "applied"):
        label = ("v1 trusts session.info" if guard == "info"
                 else "v2 requires the applied marker")
        print(f"\n  {label}:")

        # Healthy: after_begin applies the GUC.
        eng, S = build(purl, apply_guc=True, guard=guard)
        f = async_sessionmaker(eng, class_=AsyncSession, sync_session_class=S,
                               expire_on_commit=False)
        async with f() as db:
            await set_org(db, ORG_A)
            try:
                n = await count(db)
                print(f"    healthy path:  {n} row(s)  "
                      f"{OK if n == 2 else BAD}")
            except MissingTenantContext as exc:
                print(f"    healthy path:  {BAD} guard raised on a good "
                      f"request: {exc}")
        await eng.dispose()

        # Drift: session.info populated, after_begin fails to apply the GUC.
        eng, S = build(purl, apply_guc=False, guard=guard)
        f = async_sessionmaker(eng, class_=AsyncSession, sync_session_class=S,
                               expire_on_commit=False)
        async with f() as db:
            db.info[ORG_INTENT] = ORG_A  # intent recorded, SET never issued
            try:
                n = await count(db)
                print(f"    DRIFT path:    guard ALLOWED it -> {n} row(s)  "
                      f"{BAD} silent false negative")
            except MissingTenantContext as exc:
                print(f"    DRIFT path:    {OK} guard RAISED: {exc}")
        await eng.dispose()


async def main() -> None:
    base = owner_url()
    purl = (
        make_url(base).set(username=ROLE, password=PW).render_as_string(
            hide_password=False
        )
    )
    await setup(base)
    try:
        await part1(purl)
        await part2(purl)
    finally:
        await teardown(base)
        print("\n(teardown: probe_guard table + probe role dropped)")


if __name__ == "__main__":
    asyncio.run(main())
