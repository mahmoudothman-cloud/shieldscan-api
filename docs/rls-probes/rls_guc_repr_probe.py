"""Follow-up probe: what does current_setting('app.current_org_id', true)
ACTUALLY return in each state, and which policy expression is safe?

Triggered by the first probe aborting with:
    invalid input syntax for type uuid: ""
after a SET LOCAL reverted at commit — i.e. the two-argument form does NOT
reliably yield NULL, so "unset GUC -> zero rows" is not guaranteed.

Also completes experiment 3 (DISCARD ALL reset handler), which the abort cut off.
"""

from __future__ import annotations

import asyncio
import re
import uuid
from pathlib import Path

from sqlalchemy import event, text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

ENV = Path("/home/mahmoud/workspace/shieldscan-api/.env")
ROLE = "rls_probe_login"
PW = "probeonlyhex" + uuid.uuid4().hex
ORG_A = str(uuid.uuid4())
OK, BAD = "✅", "❌"

PLAIN = "current_setting('app.current_org_id', true)::uuid"
NULLIF = "NULLIF(current_setting('app.current_org_id', true), '')::uuid"


def owner_url() -> str:
    raw = next(
        ln.split("=", 1)[1].strip()
        for ln in ENV.read_text().splitlines()
        if ln.startswith("DATABASE_URL=")
    )
    return make_url(raw).set(database="shieldscan_test").render_as_string(
        hide_password=False
    )


def mask(s: object) -> str:
    return re.sub(r"[0-9a-f]{12,}", "<hex>", str(s))


async def setup(base: str) -> None:
    eng = create_async_engine(base, isolation_level="AUTOCOMMIT")
    async with eng.connect() as c:
        for t, expr in (("probe_plain", PLAIN), ("probe_nullif", NULLIF)):
            await c.execute(text(f"DROP TABLE IF EXISTS {t}"))
            await c.execute(
                text(
                    f"CREATE TABLE {t} (id serial PRIMARY KEY, "
                    "organization_id uuid NOT NULL)"
                )
            )
            await c.execute(text(f"ALTER TABLE {t} ENABLE ROW LEVEL SECURITY"))
            await c.execute(text(f"ALTER TABLE {t} FORCE ROW LEVEL SECURITY"))
            await c.execute(
                text(
                    f"CREATE POLICY tenant_isolation ON {t} "
                    f"USING (organization_id = {expr}) "
                    f"WITH CHECK (organization_id = {expr})"
                )
            )
            await c.execute(
                text(f"INSERT INTO {t} (organization_id) VALUES (:a)"), {"a": ORG_A}
            )
        await c.execute(text(f"DROP ROLE IF EXISTS {ROLE}"))
        await c.execute(
            text(
                f"CREATE ROLE {ROLE} LOGIN PASSWORD '{PW}' "
                "NOSUPERUSER NOBYPASSRLS NOINHERIT"
            )
        )
        await c.execute(text(f"GRANT USAGE ON SCHEMA public TO {ROLE}"))
        for t in ("probe_plain", "probe_nullif"):
            await c.execute(
                text(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {t} TO {ROLE}")
            )
        await c.execute(
            text(f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {ROLE}")
        )
    await eng.dispose()


async def teardown(base: str) -> None:
    eng = create_async_engine(base, isolation_level="AUTOCOMMIT")
    async with eng.connect() as c:
        for t in ("probe_plain", "probe_nullif"):
            await c.execute(text(f"DROP TABLE IF EXISTS {t}"))
        await c.execute(text(f"REVOKE ALL ON SCHEMA public FROM {ROLE}"))
        await c.execute(text(f"DROP ROLE IF EXISTS {ROLE}"))
    await eng.dispose()


async def probe_state(s: AsyncSession, label: str) -> None:
    raw = (
        await s.execute(text("SELECT current_setting('app.current_org_id', true)"))
    ).scalar()
    is_null = (
        await s.execute(
            text(
                "SELECT current_setting('app.current_org_id', true) IS NULL"
            )
        )
    ).scalar()
    print(f"    {label}: value={mask(raw)!r} IS NULL={is_null}")
    for t in ("probe_plain", "probe_nullif"):
        try:
            n = (await s.execute(text(f"SELECT count(*) FROM {t}"))).scalar()
            print(f"      {t:14s} -> {n} row(s) {OK}")
        except Exception as exc:  # noqa: BLE001
            await s.rollback()
            root = type(getattr(exc, "orig", exc)).__name__
            print(f"      {t:14s} -> {BAD} RAISES {root}: "
                  f"{mask(str(exc).splitlines()[0])[:80]}")


async def main() -> None:
    base = owner_url()
    purl = (
        make_url(base).set(username=ROLE, password=PW).render_as_string(
            hide_password=False
        )
    )
    await setup(base)
    try:
        print("=== 4. GUC representation matrix (policy expression comparison) ===")
        eng = create_async_engine(purl, pool_size=1, max_overflow=0)

        print("\n  (i) FRESH connection, GUC never set in this session:")
        async with AsyncSession(eng) as s:
            await probe_state(s, "never-set")

        print("\n  (ii) GUC SET (normal request):")
        async with AsyncSession(eng) as s:
            await s.execute(text(f"SET app.current_org_id = '{ORG_A}'"))
            await probe_state(s, "set")
            await s.rollback()

        print("\n  (iii) after SET LOCAL reverted by COMMIT "
              "(the mid-request-commit case):")
        async with AsyncSession(eng) as s:
            await s.execute(text(f"SET LOCAL app.current_org_id = '{ORG_A}'"))
            await s.commit()
            await probe_state(s, "reverted")

        print("\n  (iv) after explicit RESET (what a reset handler would do):")
        async with AsyncSession(eng) as s:
            await s.execute(text(f"SET app.current_org_id = '{ORG_A}'"))
            await s.execute(text("RESET app.current_org_id"))
            await probe_state(s, "reset")
            await s.rollback()
        await eng.dispose()

        print("\n=== 3. reset handler: does DISCARD ALL clear role + GUC? ===")
        eng2 = create_async_engine(purl, pool_size=1, max_overflow=0)

        @event.listens_for(eng2.sync_engine, "reset")
        def _reset(dbapi_connection, connection_record, reset_state):  # noqa: ANN001
            cur = dbapi_connection.cursor()
            try:
                cur.execute("DISCARD ALL")
            finally:
                cur.close()

        async with AsyncSession(eng2) as s:
            await s.execute(text(f"SET app.current_org_id = '{ORG_A}'"))
            await s.commit()
        async with AsyncSession(eng2) as s:
            raw = (
                await s.execute(
                    text("SELECT current_setting('app.current_org_id', true)")
                )
            ).scalar()
            isnull = (
                await s.execute(
                    text("SELECT current_setting('app.current_org_id', true) "
                         "IS NULL")
                )
            ).scalar()
            print(f"    after DISCARD ALL: value={mask(raw)!r} IS NULL={isnull}  "
                  f"{OK if not raw else BAD}")
            try:
                n = (
                    await s.execute(text("SELECT count(*) FROM probe_nullif"))
                ).scalar()
                print(f"    probe_nullif with cleared GUC -> {n} row(s)  "
                      f"{OK if n == 0 else BAD}")
            except Exception as exc:  # noqa: BLE001
                await s.rollback()
                print(f"    {BAD} probe_nullif RAISES: {mask(exc)}")
        await eng2.dispose()
    finally:
        await teardown(base)
        print("\n(teardown: probe tables + probe role dropped)")


if __name__ == "__main__":
    asyncio.run(main())
