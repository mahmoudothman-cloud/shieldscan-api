"""Probe 7: is the reset handler actually coupled to the guard's soundness?

Claim under test (mine): "reverting the reset handler alone makes guard v2
unsound, because a stale org_applied marker lets it pass when it shouldn't."

Counter-claim: session.info is per-session so intent is always fresh; a stale
marker from a DIFFERENT org gives match=False and raises; a stale marker from
the SAME org means the connection GUC genuinely still holds that org, so
passing is correct; and a request that forgets intent raises regardless.

Runs the full matrix with the reset handler REMOVED, checking the guard's
decision against the ACTUAL connection GUC each time — the ground truth.
Then re-runs the leak case with the guard disabled, to see what the reset
handler is still buying.
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
ORG_B = str(uuid.uuid4())
OK, BAD = "✅", "❌"
NULLIF = "NULLIF(current_setting('app.current_org_id', true), '')::uuid"
ORG_INTENT = "current_org_id"
ORG_APPLIED = "org_applied"


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
        await c.execute(text("DROP TABLE IF EXISTS probe_couple"))
        await c.execute(
            text("CREATE TABLE probe_couple (id serial PRIMARY KEY, "
                 "organization_id uuid NOT NULL, label text)")
        )
        await c.execute(text("ALTER TABLE probe_couple ENABLE ROW LEVEL SECURITY"))
        await c.execute(text("ALTER TABLE probe_couple FORCE ROW LEVEL SECURITY"))
        await c.execute(
            text(f"CREATE POLICY tenant_isolation ON probe_couple "
                 f"USING (organization_id = {NULLIF}) "
                 f"WITH CHECK (organization_id = {NULLIF})")
        )
        await c.execute(
            text("INSERT INTO probe_couple (organization_id, label) "
                 "VALUES (:a,'A-1'),(:a,'A-2'),(:b,'B-1')"),
            {"a": ORG_A, "b": ORG_B},
        )
        await c.execute(text(f"DROP ROLE IF EXISTS {ROLE}"))
        await c.execute(
            text(f"CREATE ROLE {ROLE} LOGIN PASSWORD '{PW}' "
                 "NOSUPERUSER NOBYPASSRLS NOINHERIT")
        )
        await c.execute(text(f"GRANT USAGE ON SCHEMA public TO {ROLE}"))
        await c.execute(
            text(f"GRANT SELECT, INSERT, UPDATE, DELETE ON probe_couple TO {ROLE}")
        )
        await c.execute(
            text(f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {ROLE}")
        )
    await eng.dispose()


async def teardown(base: str) -> None:
    eng = create_async_engine(base, isolation_level="AUTOCOMMIT")
    async with eng.connect() as c:
        await c.execute(text("DROP TABLE IF EXISTS probe_couple"))
        await c.execute(text(f"REVOKE ALL ON SCHEMA public FROM {ROLE}"))
        await c.execute(text(f"DROP ROLE IF EXISTS {ROLE}"))
    await eng.dispose()


def build(purl: str, *, reset_handler: bool, guard_on: bool, apply_guc: bool = True):
    eng = create_async_engine(purl, pool_size=1, max_overflow=0)

    class _S(SyncSession):
        pass

    if reset_handler:

        @event.listens_for(eng.sync_engine, "reset")
        def _reset(dbapi_connection, connection_record, reset_state):  # noqa: ANN001
            cur = dbapi_connection.cursor()
            try:
                cur.execute("ROLLBACK")
                cur.execute("RESET app.current_org_id")
            finally:
                cur.close()
            connection_record.info.pop(ORG_APPLIED, None)

    @event.listens_for(_S, "after_begin")
    def _after_begin(session, transaction, connection):  # noqa: ANN001
        org = session.info.get(ORG_INTENT)
        if org is None or not apply_guc:
            return
        connection.exec_driver_sql(
            f"SELECT set_config('app.current_org_id', '{org}', false)"
        )
        connection.connection.info[ORG_APPLIED] = org

    if guard_on:

        @event.listens_for(_S, "do_orm_execute")
        def _guard(orm_ctx):  # noqa: ANN001
            if "probe_couple" not in str(orm_ctx.statement).lower():
                return
            sess = orm_ctx.session
            intent = sess.info.get(ORG_INTENT)
            applied = sess.connection().connection.info.get(ORG_APPLIED)
            if intent is None or applied is None or applied != intent:
                raise MissingTenantContext(
                    f"intent={_s(intent)} applied={_s(applied)} "
                    f"match={applied == intent}"
                )

    return eng, _S


def _s(v):
    if v is None:
        return "None"
    return "A" if v == ORG_A else ("B" if v == ORG_B else "?")


async def run_case(f, label: str, intent: str | None) -> None:
    async with f() as db:
        if intent is not None:
            db.info[ORG_INTENT] = intent
        try:
            rows = (
                await db.execute(text("SELECT label FROM probe_couple ORDER BY id"))
            ).scalars().all()
            guc = (
                await db.execute(
                    text("SELECT current_setting('app.current_org_id', true)")
                )
            ).scalar()
            # Ground truth: what the connection GUC ACTUALLY is right now.
            truth = _s(guc) if guc else "unset"
            correct = (
                (intent == ORG_A and rows == ["A-1", "A-2"])
                or (intent == ORG_B and rows == ["B-1"])
            )
            verdict = OK if correct else BAD
            print(f"    {label:44s} PASSED  rows={rows} guc={truth} {verdict}")
        except MissingTenantContext as exc:
            print(f"    {label:44s} RAISED  ({exc})  {OK}")


async def main() -> None:
    base = owner_url()
    purl = (
        make_url(base).set(username=ROLE, password=PW).render_as_string(
            hide_password=False
        )
    )
    await setup(base)
    try:
        print("=== 10. Reset handler REMOVED, guard v2 ON — is the guard "
              "unsound? ===")
        eng, S = build(purl, reset_handler=False, guard_on=True)
        f = async_sessionmaker(eng, class_=AsyncSession, sync_session_class=S,
                               expire_on_commit=False)
        # Request 1 establishes org A and commits, leaving a stale GUC+marker.
        async with f() as db:
            db.info[ORG_INTENT] = ORG_A
            await db.execute(text("SELECT count(*) FROM probe_couple"))
            await db.commit()
        print("    (request 1 committed as org A; GUC + marker now stale on the "
              "pooled connection)")
        await run_case(f, "req2 forgets intent entirely", None)
        await run_case(f, "req2 intent=B (differs from stale marker)", ORG_B)
        await run_case(f, "req2 intent=A (matches stale marker)", ORG_A)
        await eng.dispose()

        print("\n  …and the drift case on top of a stale marker:")
        eng, S = build(purl, reset_handler=False, guard_on=True, apply_guc=False)
        f = async_sessionmaker(eng, class_=AsyncSession, sync_session_class=S,
                               expire_on_commit=False)
        eng2, S2 = build(purl, reset_handler=False, guard_on=False)
        f2 = async_sessionmaker(eng2, class_=AsyncSession, sync_session_class=S2,
                                expire_on_commit=False)
        async with f2() as db:  # prime the connection as org A
            db.info[ORG_INTENT] = ORG_A
            await db.execute(text("SELECT count(*) FROM probe_couple"))
            await db.commit()
        await eng2.dispose()
        await run_case(f, "req2 intent=A, after_begin FAILS to apply", ORG_A)
        await eng.dispose()

        print("\n=== 11. What the reset handler still buys: guard OFF "
              "(kill-switch flipped) ===")
        for rh in (False, True):
            eng, S = build(purl, reset_handler=rh, guard_on=False)
            f = async_sessionmaker(eng, class_=AsyncSession, sync_session_class=S,
                                   expire_on_commit=False)
            async with f() as db:
                db.info[ORG_INTENT] = ORG_A
                await db.execute(text("SELECT count(*) FROM probe_couple"))
                await db.commit()
            async with f() as db:  # request 2 forgets everything
                rows = (
                    await db.execute(
                        text("SELECT label FROM probe_couple ORDER BY id")
                    )
                ).scalars().all()
                state = "WITH reset handler   " if rh else "WITHOUT reset handler"
                mark = OK if not rows else BAD + " LEAK"
                print(f"    {state}: req2 (no context) sees {rows}  {mark}")
            await eng.dispose()
    finally:
        await teardown(base)
        print("\n(teardown: probe_couple table + probe role dropped)")


if __name__ == "__main__":
    asyncio.run(main())
