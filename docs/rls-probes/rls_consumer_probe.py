"""Probe 4: does the GUC survive the AI pipeline's flush-per-vulnerability
sequence when the app connects AS the app role, with the ROLLBACK+RESET
handler installed?

Mirrors ai_pipeline_consumer._process faithfully:
    async with session_factory() as db:
        await db.execute(text(f"SET app.current_org_id = '{org}'"))   # non-LOCAL
        ... pipeline: flush per vulnerability, ONE commit at the end ...
    # session closes -> connection returns to pool -> reset handler fires

Then re-uses the SAME pooled connection for a second event (different org) and
a third event that FORGETS to set the GUC, which is the failure mode that must
degrade to zero rows rather than to another tenant's data.
"""

from __future__ import annotations

import asyncio
import re
import uuid
from pathlib import Path

from sqlalchemy import event, text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

ENV = Path("/home/mahmoud/workspace/shieldscan-api/.env")
ROLE = "rls_probe_login"
PW = "probeonlyhex" + uuid.uuid4().hex
ORG_A = str(uuid.uuid4())
ORG_B = str(uuid.uuid4())
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
    return re.sub(r"[0-9a-f-]{20,}", "<uuid>", str(s))


async def setup(base: str) -> None:
    eng = create_async_engine(base, isolation_level="AUTOCOMMIT")
    async with eng.connect() as c:
        await c.execute(text("DROP TABLE IF EXISTS probe_vuln"))
        await c.execute(
            text(
                "CREATE TABLE probe_vuln (id serial PRIMARY KEY, "
                "organization_id uuid NOT NULL, title text)"
            )
        )
        await c.execute(text("ALTER TABLE probe_vuln ENABLE ROW LEVEL SECURITY"))
        await c.execute(text("ALTER TABLE probe_vuln FORCE ROW LEVEL SECURITY"))
        await c.execute(
            text(
                f"CREATE POLICY tenant_isolation ON probe_vuln "
                f"USING (organization_id = {NULLIF}) "
                f"WITH CHECK (organization_id = {NULLIF})"
            )
        )
        # Pre-existing row per org, seeded as superuser (bypasses RLS).
        await c.execute(
            text(
                "INSERT INTO probe_vuln (organization_id, title) "
                "VALUES (:a, 'A-preexisting'), (:b, 'B-preexisting')"
            ),
            {"a": ORG_A, "b": ORG_B},
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
            text(f"GRANT SELECT, INSERT, UPDATE, DELETE ON probe_vuln TO {ROLE}")
        )
        await c.execute(
            text(f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {ROLE}")
        )
    await eng.dispose()


async def teardown(base: str) -> None:
    eng = create_async_engine(base, isolation_level="AUTOCOMMIT")
    async with eng.connect() as c:
        await c.execute(text("DROP TABLE IF EXISTS probe_vuln"))
        await c.execute(text(f"REVOKE ALL ON SCHEMA public FROM {ROLE}"))
        await c.execute(text(f"DROP ROLE IF EXISTS {ROLE}"))
    await eng.dispose()


def build_engine(purl: str):
    """Phase-3 shape: connect AS the app role + ROLLBACK-then-RESET handler."""
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


async def consumer_event(factory, org: str, n_vulns: int, label: str) -> None:
    """Faithful mirror of ai_pipeline_consumer._process."""
    async with factory() as db:
        await db.execute(text(f"SET app.current_org_id = '{org}'"))

        start = (await db.execute(text("SELECT count(*) FROM probe_vuln"))).scalar()
        # Pipeline: flush per Vulnerability (D-deviation #1), no intermediate commit.
        for i in range(n_vulns):
            await db.execute(
                text(
                    "INSERT INTO probe_vuln (organization_id, title) "
                    "VALUES (:o, :t)"
                ),
                {"o": org, "t": f"{label}-vuln-{i}"},
            )
            await db.flush()
            mid = (
                await db.execute(text("SELECT count(*) FROM probe_vuln"))
            ).scalar()
            guc_live = (
                await db.execute(
                    text("SELECT current_setting('app.current_org_id', true)")
                )
            ).scalar()
            if guc_live != org:
                print(f"    {BAD} GUC LOST mid-flush at vuln {i}: {mask(guc_live)}")
                return
            if mid != start + i + 1:
                print(f"    {BAD} visibility wrong after flush {i}: {mid}")
                return
        await db.flush()  # pipeline's final flush
        await db.commit()  # consumer's single commit
        end = (await db.execute(text("SELECT count(*) FROM probe_vuln"))).scalar()
        print(
            f"    {label}: {n_vulns} flushes, GUC held throughout, "
            f"{start} -> {start + n_vulns} rows; post-commit read = {end}"
        )


async def main() -> None:
    base = owner_url()
    purl = (
        make_url(base).set(username=ROLE, password=PW).render_as_string(
            hide_password=False
        )
    )
    await setup(base)
    try:
        eng = build_engine(purl)
        factory = async_sessionmaker(eng, class_=AsyncSession, expire_on_commit=False)

        print("=== 6. AIPipelineConsumer sequence, connected AS the app role ===")
        print("  event 1 (org A, 3 vulns):")
        await consumer_event(factory, ORG_A, 3, "orgA")

        print("\n  event 2 (org B) — SAME pooled connection, different tenant:")
        await consumer_event(factory, ORG_B, 2, "orgB")

        print("\n  cross-tenant check after both events:")
        async with factory() as db:
            await db.execute(text(f"SET app.current_org_id = '{ORG_A}'"))
            a = (await db.execute(text("SELECT count(*) FROM probe_vuln"))).scalar()
            titles = (
                await db.execute(text("SELECT title FROM probe_vuln ORDER BY id"))
            ).scalars().all()
            print(f"    org A sees {a} row(s): {titles}")
            leaked = [t for t in titles if t and t.startswith(("orgB", "B-"))]
            print(f"    org B rows visible to org A: {leaked}  "
                  f"{BAD if leaked else OK}")

        print("\n  event 3 — consumer FORGETS to set the GUC (the failure mode):")
        async with factory() as db:
            guc = (
                await db.execute(
                    text("SELECT current_setting('app.current_org_id', true)")
                )
            ).scalar()
            n = (await db.execute(text("SELECT count(*) FROM probe_vuln"))).scalar()
            print(f"    inherited GUC={mask(guc)!r}, rows visible = {n}")
            if n == 0:
                print(f"    {OK} fails CLOSED: zero rows, no error, no other "
                      "tenant's data")
            else:
                print(f"    {BAD} inherited another tenant's context")

        print("\n  event 4 — _fail_scan's nested second session pattern:")
        async with factory() as db:
            await db.execute(text(f"SET app.current_org_id = '{ORG_A}'"))
            try:
                raise RuntimeError("simulated pipeline crash")
            except RuntimeError:
                pass
        async with factory() as fail_db:  # same pooled connection
            await fail_db.execute(text(f"SET app.current_org_id = '{ORG_A}'"))
            n = (
                await fail_db.execute(text("SELECT count(*) FROM probe_vuln"))
            ).scalar()
            await fail_db.commit()
            print(f"    _fail_scan session sees {n} org-A row(s)  "
                  f"{OK if n else BAD}")
        await eng.dispose()
    finally:
        await teardown(base)
        print("\n(teardown: probe_vuln table + probe role dropped)")


if __name__ == "__main__":
    asyncio.run(main())
