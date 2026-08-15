"""Third probe: which reset handler reliably clears the GUC, including when a
connection is returned to the pool mid-transaction, and without breaking
asyncpg's prepared-statement cache.

Prompted by the second probe emitting:
    ActiveSQLTransactionError: DISCARD ALL cannot run inside a transaction block
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
        await c.execute(text("DROP TABLE IF EXISTS probe_reset"))
        await c.execute(
            text(
                "CREATE TABLE probe_reset (id serial PRIMARY KEY, "
                "organization_id uuid NOT NULL)"
            )
        )
        await c.execute(text("ALTER TABLE probe_reset ENABLE ROW LEVEL SECURITY"))
        await c.execute(text("ALTER TABLE probe_reset FORCE ROW LEVEL SECURITY"))
        await c.execute(
            text(
                f"CREATE POLICY tenant_isolation ON probe_reset "
                f"USING (organization_id = {NULLIF}) "
                f"WITH CHECK (organization_id = {NULLIF})"
            )
        )
        await c.execute(
            text("INSERT INTO probe_reset (organization_id) VALUES (:a)"),
            {"a": ORG_A},
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
            text(f"GRANT SELECT, INSERT, UPDATE, DELETE ON probe_reset TO {ROLE}")
        )
        await c.execute(
            text(f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {ROLE}")
        )
    await eng.dispose()


async def teardown(base: str) -> None:
    eng = create_async_engine(base, isolation_level="AUTOCOMMIT")
    async with eng.connect() as c:
        await c.execute(text("DROP TABLE IF EXISTS probe_reset"))
        await c.execute(text(f"REVOKE ALL ON SCHEMA public FROM {ROLE}"))
        await c.execute(text(f"DROP ROLE IF EXISTS {ROLE}"))
    await eng.dispose()


def make_engine(purl: str, handler_sql: list[str] | None):
    eng = create_async_engine(purl, pool_size=1, max_overflow=0)
    if handler_sql is not None:

        @event.listens_for(eng.sync_engine, "reset")
        def _reset(dbapi_connection, connection_record, reset_state):  # noqa: ANN001
            cur = dbapi_connection.cursor()
            try:
                for sql in handler_sql:
                    cur.execute(sql)
            finally:
                cur.close()

    return eng


async def leak_check(eng, label: str, *, leave_txn_open: bool) -> None:
    """Set the GUC in 'request 1', then see what 'request 2' inherits."""
    try:
        async with AsyncSession(eng) as s:
            await s.execute(text(f"SET app.current_org_id = '{ORG_A}'"))
            await s.execute(text("SELECT count(*) FROM probe_reset"))
            if not leave_txn_open:
                await s.commit()
            # leave_txn_open=True: session closes with an OPEN transaction —
            # the case a mid-request exception produces.
    except Exception as exc:  # noqa: BLE001
        print(f"    {label}: request 1 errored: {mask(exc)[:90]}")
        return

    try:
        async with AsyncSession(eng) as s:
            raw = (
                await s.execute(
                    text("SELECT current_setting('app.current_org_id', true)")
                )
            ).scalar()
            n = (await s.execute(text("SELECT count(*) FROM probe_reset"))).scalar()
            leaked = bool(raw)
            print(
                f"    {label}: inherited GUC={mask(raw)!r} rows={n}  "
                f"{BAD + ' LEAK' if leaked else OK + ' clean'}"
            )
    except Exception as exc:  # noqa: BLE001
        root = type(getattr(exc, "orig", exc)).__name__
        print(f"    {label}: request 2 {BAD} ERRORED {root}: {mask(exc)[:80]}")


async def churn_check(eng, label: str) -> None:
    """Prepared-statement-cache safety: many checkouts through the handler."""
    try:
        for i in range(12):
            async with AsyncSession(eng) as s:
                await s.execute(text(f"SET app.current_org_id = '{ORG_A}'"))
                await s.execute(text("SELECT count(*) FROM probe_reset"))
                await s.execute(
                    text("SELECT id FROM probe_reset WHERE organization_id = :o"),
                    {"o": ORG_A},
                )
                await s.commit()
        print(f"    {label}: 12 checkout cycles {OK} no statement-cache errors")
    except Exception as exc:  # noqa: BLE001
        root = type(getattr(exc, "orig", exc)).__name__
        print(f"    {label}: {BAD} failed after churn: {root}: {mask(exc)[:80]}")


async def main() -> None:
    base = owner_url()
    purl = (
        make_url(base).set(username=ROLE, password=PW).render_as_string(
            hide_password=False
        )
    )
    await setup(base)
    try:
        candidates = {
            "no handler (default rollback)": None,
            "DISCARD ALL": ["DISCARD ALL"],
            "ROLLBACK; DISCARD ALL": ["ROLLBACK", "DISCARD ALL"],
            "RESET app.current_org_id": ["RESET app.current_org_id"],
            "ROLLBACK; RESET ...": ["ROLLBACK", "RESET app.current_org_id"],
        }

        print("=== 5a. clean check-in (request 1 committed) ===")
        for label, sql in candidates.items():
            eng = make_engine(purl, sql)
            await leak_check(eng, f"{label:30s}", leave_txn_open=False)
            await eng.dispose()

        print("\n=== 5b. check-in with an OPEN transaction (mid-request error) ===")
        for label, sql in candidates.items():
            eng = make_engine(purl, sql)
            await leak_check(eng, f"{label:30s}", leave_txn_open=True)
            await eng.dispose()

        print("\n=== 5c. prepared-statement-cache safety under churn ===")
        for label, sql in candidates.items():
            eng = make_engine(purl, sql)
            await churn_check(eng, f"{label:30s}")
            await eng.dispose()
    finally:
        await teardown(base)
        print("\n(teardown: probe_reset table + probe role dropped)")


if __name__ == "__main__":
    asyncio.run(main())
