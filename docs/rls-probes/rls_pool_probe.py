"""Empirical probe for the RLS session-role plan. Read-only w.r.t. the repo and
the dev database: all objects live in shieldscan_test and are dropped at the end.

Answers three questions by demonstration:
  1. Does a non-LOCAL SET GUC (and SET ROLE) survive connection check-in and
     become visible to the next checkout of that same physical connection?
  2. Does SET LOCAL survive the AI pipeline's flush-per-vuln pattern, and what
     does a mid-request commit do to it?
  3. What does reset_on_return actually clear, and can a custom reset handler
     reliably clear both the role and a custom GUC?
"""

from __future__ import annotations

import asyncio
import re
import sys
import uuid
from pathlib import Path

from sqlalchemy import event, text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

ENV = Path("/home/mahmoud/workspace/shieldscan-api/.env")
PROBE_ROLE = "rls_probe_login"
PROBE_PW = "probeonlyhex" + uuid.uuid4().hex  # throwaway, dropped at teardown
ORG_A = str(uuid.uuid4())
ORG_B = str(uuid.uuid4())

OK, BAD = "✅", "❌"


def owner_url() -> str:
    raw = next(
        line.split("=", 1)[1].strip()
        for line in ENV.read_text().splitlines()
        if line.startswith("DATABASE_URL=")
    )
    return make_url(raw).set(database="shieldscan_test").render_as_string(
        hide_password=False
    )


def probe_url(base: str) -> str:
    return (
        make_url(base)
        .set(username=PROBE_ROLE, password=PROBE_PW)
        .render_as_string(hide_password=False)
    )


def mask(s: object) -> str:
    return re.sub(r"[0-9a-f]{12,}", "<hex>", str(s))


async def setup(base: str) -> None:
    eng = create_async_engine(base, isolation_level="AUTOCOMMIT")
    async with eng.connect() as c:
        await c.execute(text("DROP TABLE IF EXISTS rls_probe"))
        await c.execute(
            text(
                "CREATE TABLE rls_probe (id serial PRIMARY KEY, "
                "organization_id uuid NOT NULL, label text)"
            )
        )
        await c.execute(text("ALTER TABLE rls_probe ENABLE ROW LEVEL SECURITY"))
        await c.execute(text("ALTER TABLE rls_probe FORCE ROW LEVEL SECURITY"))
        # The TWO-ARGUMENT form under evaluation (fork decision (a)):
        # missing GUC -> NULL -> predicate NULL -> zero rows, never an error.
        await c.execute(
            text(
                "CREATE POLICY tenant_isolation ON rls_probe "
                "USING (organization_id = "
                "current_setting('app.current_org_id', true)::uuid) "
                "WITH CHECK (organization_id = "
                "current_setting('app.current_org_id', true)::uuid)"
            )
        )
        await c.execute(
            text(
                f"DROP ROLE IF EXISTS {PROBE_ROLE}"
            )
        )
        await c.execute(
            text(
                f"CREATE ROLE {PROBE_ROLE} LOGIN PASSWORD '{PROBE_PW}' "
                f"NOSUPERUSER NOBYPASSRLS NOINHERIT"
            )
        )
        await c.execute(text(f"GRANT USAGE ON SCHEMA public TO {PROBE_ROLE}"))
        await c.execute(
            text(f"GRANT SELECT, INSERT, UPDATE, DELETE ON rls_probe TO {PROBE_ROLE}")
        )
        await c.execute(
            text(
                "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public "
                f"TO {PROBE_ROLE}"
            )
        )
        # Seeded as superuser (bypasses RLS): one row per org.
        await c.execute(
            text(
                "INSERT INTO rls_probe (organization_id, label) "
                "VALUES (:a, 'org-A row'), (:b, 'org-B row')"
            ),
            {"a": ORG_A, "b": ORG_B},
        )
    await eng.dispose()


async def teardown(base: str) -> None:
    eng = create_async_engine(base, isolation_level="AUTOCOMMIT")
    async with eng.connect() as c:
        await c.execute(text("DROP TABLE IF EXISTS rls_probe"))
        await c.execute(text(f"REVOKE ALL ON SCHEMA public FROM {PROBE_ROLE}"))
        await c.execute(text(f"DROP ROLE IF EXISTS {PROBE_ROLE}"))
    await eng.dispose()


# ---------------------------------------------------------------- experiment 1


async def exp1_guc_leak_across_checkin(purl: str) -> None:
    print("\n=== 1. Does a non-LOCAL SET survive check-in and leak to the next "
          "checkout? ===")
    # pool_size=1 / max_overflow=0 guarantees both sessions get the SAME
    # physical connection — exactly what a busy pool does by chance.
    eng = create_async_engine(purl, pool_size=1, max_overflow=0)

    async with AsyncSession(eng) as s1:
        await s1.execute(text(f"SET app.current_org_id = '{ORG_A}'"))
        n = (await s1.execute(text("SELECT count(*) FROM rls_probe"))).scalar()
        print(f"  request 1 (org A): sees {n} row(s)")
        await s1.commit()  # transaction ends; session closes -> connection returns

    async with AsyncSession(eng) as s2:
        leaked = (
            await s2.execute(
                text("SELECT current_setting('app.current_org_id', true)")
            )
        ).scalar()
        n = (await s2.execute(text("SELECT count(*) FROM rls_probe"))).scalar()
        verdict = BAD if leaked else OK
        print(f"  request 2 (NO GUC set): current_setting -> {mask(leaked)}")
        print(f"  request 2 sees {n} row(s)  {verdict}")
        if leaked == ORG_A:
            print(f"  {BAD} LEAK CONFIRMED: request 2 inherited request 1's tenant "
                  "context.")
    await eng.dispose()


async def exp1b_set_role_leak(base: str) -> None:
    print("\n--- 1b. same question for SET ROLE (the alternative fork) ---")
    eng = create_async_engine(base, pool_size=1, max_overflow=0)
    async with AsyncSession(eng) as s1:
        await s1.execute(text(f"SET ROLE {PROBE_ROLE}"))
        who = (await s1.execute(text("SELECT current_user"))).scalar()
        print(f"  request 1 after SET ROLE: current_user = {who}")
        await s1.commit()
    async with AsyncSession(eng) as s2:
        who = (await s2.execute(text("SELECT current_user"))).scalar()
        mark = BAD if who == PROBE_ROLE else OK
        print(f"  request 2 (no SET ROLE): current_user = {who}  {mark}")
    await eng.dispose()


# ---------------------------------------------------------------- experiment 2


async def exp2_set_local(purl: str) -> None:
    print("\n=== 2. Does SET LOCAL survive the pipeline's flush-per-vuln "
          "pattern? ===")
    eng = create_async_engine(purl, pool_size=1, max_overflow=0)

    async with AsyncSession(eng) as s:
        await s.execute(text(f"SET LOCAL app.current_org_id = '{ORG_A}'"))
        n = (await s.execute(text("SELECT count(*) FROM rls_probe"))).scalar()
        print(f"  after SET LOCAL:            sees {n} row(s)")

        # The AI pipeline's D-deviation #1: flush per Vulnerability so the
        # raw_finding FK resolves, all inside the consumer's ONE transaction.
        for i in range(3):
            await s.execute(
                text(
                    "INSERT INTO rls_probe (organization_id, label) "
                    "VALUES (:o, :l)"
                ),
                {"o": ORG_A, "l": f"flushed-{i}"},
            )
            await s.flush()
        n = (await s.execute(text("SELECT count(*) FROM rls_probe"))).scalar()
        print(f"  after 3x flush (no commit): sees {n} row(s)  "
              f"{OK if n else BAD}")

        await s.commit()  # <- the consumer's single commit ends the transaction
        n = (await s.execute(text("SELECT count(*) FROM rls_probe"))).scalar()
        guc = (
            await s.execute(
                text("SELECT current_setting('app.current_org_id', true)")
            )
        ).scalar()
        print(f"  AFTER commit:               sees {n} row(s), GUC={mask(guc)}  "
              f"{BAD if n == 0 else OK}")
        if n == 0:
            print(f"  {BAD} SET LOCAL is cleared by commit — any code that "
                  "commits mid-request then queries a tenant table breaks.")
    await eng.dispose()


# ---------------------------------------------------------------- experiment 3


async def exp3_reset_handler(purl: str) -> None:
    print("\n=== 3. What does reset_on_return clear, and can a custom handler "
          "clear role + GUC? ===")

    print("  (a) default reset_on_return='rollback':")
    eng = create_async_engine(purl, pool_size=1, max_overflow=0)
    async with AsyncSession(eng) as s:
        await s.execute(text(f"SET app.current_org_id = '{ORG_A}'"))
        await s.commit()
    async with AsyncSession(eng) as s:
        guc = (
            await s.execute(
                text("SELECT current_setting('app.current_org_id', true)")
            )
        ).scalar()
        print(f"      GUC after ROLLBACK-on-return: {mask(guc)}  "
              f"{BAD if guc else OK}")
    await eng.dispose()

    print("  (b) custom reset handler issuing DISCARD ALL:")
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
        guc = (
            await s.execute(
                text("SELECT current_setting('app.current_org_id', true)")
            )
        ).scalar()
        print(f"      GUC after DISCARD ALL:        {mask(guc)}  "
              f"{OK if not guc else BAD}")
    await eng2.dispose()


async def main() -> None:
    base = owner_url()
    purl = probe_url(base)
    await setup(base)
    try:
        await exp1_guc_leak_across_checkin(purl)
        await exp1b_set_role_leak(base)
        await exp2_set_local(purl)
        await exp3_reset_handler(purl)
    finally:
        await teardown(base)
        print("\n(teardown: rls_probe table + rls_probe_login role dropped)")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as exc:  # noqa: BLE001
        print(f"\n{BAD} probe aborted: {type(exc).__name__}: {mask(exc)}")
        sys.exit(1)
