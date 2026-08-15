"""Probe 8: do ORM UPDATE and DELETE fail loudly with no tenant context?

Established already:
  * do_orm_execute does NOT fire for unit-of-work flush -> the guard covers
    reads only.
  * INSERT is caught by the policy's WITH CHECK -> loud RLS violation.

Open question: UPDATE and DELETE of an EXISTING row. With no GUC the policy's
USING clause makes zero rows visible, so the statement matches nothing. Does
SQLAlchemy notice (StaleDataError) or does it silently affect 0 rows and
report success?

Run as the real non-superuser app role against a real RLS'd table.
"""

from __future__ import annotations

import asyncio
import uuid
from pathlib import Path

from sqlalchemy import event, text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session as SyncSession, mapped_column

ENV = Path("/home/mahmoud/workspace/shieldscan-api/.env")
OK, BAD = "✅", "❌"
NULLIF = "NULLIF(current_setting('app.current_org_id', true), '')::uuid"
ORG_A = str(uuid.uuid4())
INTENT = "tenant_org_id"


def _env(key: str) -> str:
    return next(
        ln.split("=", 1)[1].strip()
        for ln in ENV.read_text().splitlines()
        if ln.startswith(f"{key}=")
    )


def owner_url() -> str:
    return (
        make_url(_env("DATABASE_URL"))
        .set(database="shieldscan_test")
        .render_as_string(hide_password=False)
    )


def app_url() -> str:
    return (
        make_url(owner_url())
        .set(username="shieldscan_app", password=_env("APP_DB_PASSWORD"))
        .render_as_string(hide_password=False)
    )


class Base(DeclarativeBase):
    pass


class Row(Base):
    __tablename__ = "probe_upd"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    organization_id: Mapped[uuid.UUID]
    label: Mapped[str]


class TSession(SyncSession):
    pass


@event.listens_for(TSession, "after_begin")
def _reapply(session, transaction, connection):  # noqa: ANN001
    org = session.info.get(INTENT)
    if org is not None:
        connection.exec_driver_sql(
            f"SELECT set_config('app.current_org_id', '{org}', false)"
        )


async def setup(owner: str) -> None:
    eng = create_async_engine(owner, isolation_level="AUTOCOMMIT")
    async with eng.connect() as c:
        await c.execute(text("DROP TABLE IF EXISTS probe_upd"))
        await c.execute(
            text(
                "CREATE TABLE probe_upd (id serial PRIMARY KEY, "
                "organization_id uuid NOT NULL, label text NOT NULL)"
            )
        )
        await c.execute(text("ALTER TABLE probe_upd ENABLE ROW LEVEL SECURITY"))
        await c.execute(text("ALTER TABLE probe_upd FORCE ROW LEVEL SECURITY"))
        await c.execute(
            text(
                f"CREATE POLICY tenant_isolation ON probe_upd "
                f"USING (organization_id = {NULLIF}) "
                f"WITH CHECK (organization_id = {NULLIF})"
            )
        )
        await c.execute(
            text("GRANT SELECT, INSERT, UPDATE, DELETE ON probe_upd TO shieldscan_app")
        )
        await c.execute(
            text("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public "
                 "TO shieldscan_app")
        )
    await eng.dispose()


async def teardown(owner: str) -> None:
    eng = create_async_engine(owner, isolation_level="AUTOCOMMIT")
    async with eng.connect() as c:
        await c.execute(text("DROP TABLE IF EXISTS probe_upd"))
    await eng.dispose()


async def _seed(factory) -> int:
    async with factory() as db:
        db.info[INTENT] = ORG_A
        await db.execute(
            text("SELECT set_config('app.current_org_id', :o, false)"), {"o": ORG_A}
        )
        row = Row(organization_id=uuid.UUID(ORG_A), label="original")
        db.add(row)
        await db.flush()
        rid = row.id
        await db.commit()
        return rid


async def _row_state(owner: str, rid: int) -> tuple[bool, str | None]:
    """Ground truth, read as the OWNER (bypasses RLS)."""
    eng = create_async_engine(owner)
    async with eng.connect() as c:
        r = (
            await c.execute(
                text("SELECT label FROM probe_upd WHERE id = :i"), {"i": rid}
            )
        ).first()
    await eng.dispose()
    return (r is not None, r[0] if r else None)


async def main() -> None:
    owner, app = owner_url(), app_url()
    await setup(owner)
    try:
        eng = create_async_engine(app)
        factory = async_sessionmaker(
            eng, class_=AsyncSession, sync_session_class=TSession,
            expire_on_commit=False,
        )

        # ---------------- UPDATE ----------------
        rid = await _seed(factory)
        print("=== 12. ORM UPDATE of an existing row with NO tenant context ===")
        async with factory() as db:
            db.info[INTENT] = ORG_A
            await db.execute(
                text("SELECT set_config('app.current_org_id', :o, false)"),
                {"o": ORG_A},
            )
            obj = await db.get(Row, rid)
            assert obj is not None, "precondition: row loaded with context"

            # Lose the tenant context — the "SET without intent" / cleared-GUC case.
            db.info.pop(INTENT, None)
            await db.execute(
                text("SELECT set_config('app.current_org_id', '', false)")
            )

            obj.label = "MUTATED-WITHOUT-CONTEXT"
            try:
                await db.flush()
                await db.commit()
                print(f"  flush+commit SUCCEEDED  {BAD}")
            except Exception as exc:  # noqa: BLE001
                print(f"  raised {type(exc).__name__}: {str(exc).splitlines()[0][:88]}")
                await db.rollback()
        exists, label = await _row_state(owner, rid)
        silent = label == "original"
        print(f"  ground truth: exists={exists} label={label!r}")
        print(f"  -> {OK + ' loud (raised, row untouched)' if silent else BAD} "
              if silent else f"  -> {BAD} row was modified without context")

        # ---------------- DELETE ----------------
        rid2 = await _seed(factory)
        print("\n=== 13. ORM DELETE of an existing row with NO tenant context ===")
        async with factory() as db:
            db.info[INTENT] = ORG_A
            await db.execute(
                text("SELECT set_config('app.current_org_id', :o, false)"),
                {"o": ORG_A},
            )
            obj = await db.get(Row, rid2)
            assert obj is not None

            db.info.pop(INTENT, None)
            await db.execute(
                text("SELECT set_config('app.current_org_id', '', false)")
            )

            await db.delete(obj)
            try:
                await db.flush()
                await db.commit()
                print(f"  flush+commit SUCCEEDED  {BAD}")
            except Exception as exc:  # noqa: BLE001
                print(f"  raised {type(exc).__name__}: {str(exc).splitlines()[0][:88]}")
                await db.rollback()
        exists, label = await _row_state(owner, rid2)
        print(f"  ground truth: exists={exists} label={label!r}")
        print(f"  -> {OK + ' row survived' if exists else BAD + ' row was deleted'}")

        # ------------- Core UPDATE/DELETE via session.execute (guard territory) -----
        print("\n=== 14. Core update()/delete() via session.execute (does the "
              "guard see these?) ===")
        from sqlalchemy import delete as sa_delete, update as sa_update

        rid3 = await _seed(factory)
        for label, stmt in (
            ("update()", sa_update(Row).where(Row.id == rid3).values(label="core-upd")),
            ("delete()", sa_delete(Row).where(Row.id == rid3)),
        ):
            async with factory() as db:
                db.info.pop(INTENT, None)
                try:
                    res = await db.execute(stmt)
                    await db.commit()
                    print(f"  {label}: SUCCEEDED, rowcount={res.rowcount}  "
                          f"{BAD if res.rowcount == 0 else OK}")
                except Exception as exc:  # noqa: BLE001
                    print(f"  {label}: raised {type(exc).__name__}  {OK}")
                    await db.rollback()
        await eng.dispose()
    finally:
        await teardown(owner)
        print("\n(teardown: probe_upd dropped)")


if __name__ == "__main__":
    asyncio.run(main())
