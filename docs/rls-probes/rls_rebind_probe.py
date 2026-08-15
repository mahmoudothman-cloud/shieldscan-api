"""Probe 5: the commit-then-read regression, and the remedy.

Probe 4 showed that with the ROLLBACK+RESET handler installed, a commit inside
a request releases the connection, the handler clears the GUC, and every
subsequent read in that same session returns zero rows. That is the
projects.py:542 (commit) -> :551 (read ProjectCredential) pattern.

Compares three configurations against the real-world sequence:
    SET GUC -> INSERT -> COMMIT -> SELECT (must still see the row)

  A. reset handler only                 (the Phase-3 plan as written)
  B. reset handler + after_begin re-apply from session.info
  C. reset handler + session pinned to one connection for the request
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
ORG_KEY = "current_org_id"


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
        await c.execute(text("DROP TABLE IF EXISTS probe_rebind"))
        await c.execute(
            text(
                "CREATE TABLE probe_rebind (id serial PRIMARY KEY, "
                "organization_id uuid NOT NULL, label text)"
            )
        )
        await c.execute(text("ALTER TABLE probe_rebind ENABLE ROW LEVEL SECURITY"))
        await c.execute(text("ALTER TABLE probe_rebind FORCE ROW LEVEL SECURITY"))
        await c.execute(
            text(
                f"CREATE POLICY tenant_isolation ON probe_rebind "
                f"USING (organization_id = {NULLIF}) "
                f"WITH CHECK (organization_id = {NULLIF})"
            )
        )
        await c.execute(text(f"DROP ROLE IF EXISTS {ROLE}"))
        await c.execute(
            text(
                f"CREATE ROLE {ROLE} LOGIN PASSWORD '{PW}' "
                "NOSUPERUSER NOBYPASSRLS NOINHERIT"
            )
        )
        await c.execute(text(f"GRANT USAGE ON SCHEMA public TO {ROLE}"))
        await c.execute(
            text(f"GRANT SELECT, INSERT, UPDATE, DELETE ON probe_rebind TO {ROLE}")
        )
        await c.execute(
            text(f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {ROLE}")
        )
    await eng.dispose()


async def teardown(base: str) -> None:
    eng = create_async_engine(base, isolation_level="AUTOCOMMIT")
    async with eng.connect() as c:
        await c.execute(text("DROP TABLE IF EXISTS probe_rebind"))
        await c.execute(text(f"REVOKE ALL ON SCHEMA public FROM {ROLE}"))
        await c.execute(text(f"DROP ROLE IF EXISTS {ROLE}"))
    await eng.dispose()


def base_engine(purl: str):
    eng = create_async_engine(purl, pool_size=1, max_overflow=0)

    @event.listens_for(eng.sync_engine, "reset")
    def _reset(dbapi_connection, connection_record, reset_state):  # noqa: ANN001
        cur = dbapi_connection.cursor()
        try:
            cur.execute("ROLLBACK")
            cur.execute("RESET app.current_org_id")
        finally:
            cur.close()

    return eng


def add_rebind(factory) -> None:
    """Re-apply the request's org GUC at the start of EVERY transaction.

    after_begin is a sync-Session event; AsyncSession proxies .info to the sync
    session it wraps. In the real implementation this would be registered on a
    dedicated sync_session_class rather than globally.
    """

    @event.listens_for(SyncSession, "after_begin")
    def _after_begin(session: SyncSession, transaction, connection):  # noqa: ANN001
        org = session.info.get(ORG_KEY)
        if org is not None:
            connection.exec_driver_sql(f"SET app.current_org_id = '{org}'")


async def set_org(db: AsyncSession, org: str) -> None:
    """What the auth dependency / consumer would call instead of a raw SET."""
    db.info[ORG_KEY] = org
    await db.execute(text(f"SET app.current_org_id = '{org}'"))


async def commit_then_read(factory, label: str, *, pinned_conn=None) -> None:
    maker = (
        (lambda: AsyncSession(bind=pinned_conn, expire_on_commit=False))
        if pinned_conn is not None
        else factory
    )
    db = maker()
    try:
        await set_org(db, ORG_A)
        await db.execute(
            text("INSERT INTO probe_rebind (organization_id, label) "
                 "VALUES (:o, 'row')"),
            {"o": ORG_A},
        )
        await db.commit()  # <- projects.py:542
        n = (await db.execute(text("SELECT count(*) FROM probe_rebind"))).scalar()
        # <- projects.py:551 reads AFTER the commit
        print(f"    {label}: post-commit read sees {n} row(s)  "
              f"{OK if n else BAD + '  REGRESSION'}")
    finally:
        await db.close()


async def main() -> None:
    base = owner_url()
    purl = (
        make_url(base).set(username=ROLE, password=PW).render_as_string(
            hide_password=False
        )
    )
    await setup(base)
    try:
        print("=== 7. commit-then-read (projects.py:542 -> :551) ===")

        eng = base_engine(purl)
        f = async_sessionmaker(eng, class_=AsyncSession, expire_on_commit=False)
        await commit_then_read(f, "A. reset handler only            ")
        await eng.dispose()

        eng = base_engine(purl)
        f = async_sessionmaker(eng, class_=AsyncSession, expire_on_commit=False)
        add_rebind(f)
        await commit_then_read(f, "B. + after_begin re-apply        ")

        print("\n  B also has to stay clean across requests (no leak):")
        async with f() as db:  # fresh session, no org set
            guc = (
                await db.execute(
                    text("SELECT current_setting('app.current_org_id', true)")
                )
            ).scalar()
            n = (await db.execute(text("SELECT count(*) FROM probe_rebind"))).scalar()
            print(f"    next request: GUC={guc!r} rows={n}  "
                  f"{OK + ' clean' if n == 0 else BAD + ' LEAK'}")
        await eng.dispose()

        eng = base_engine(purl)
        f = async_sessionmaker(eng, class_=AsyncSession, expire_on_commit=False)
        conn = await eng.connect()
        await commit_then_read(f, "C. pinned connection             ",
                               pinned_conn=conn)
        await conn.close()
        await eng.dispose()
    finally:
        await teardown(base)
        print("\n(teardown: probe_rebind table + probe role dropped)")


if __name__ == "__main__":
    asyncio.run(main())
