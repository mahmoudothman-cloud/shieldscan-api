"""RLS: null-safe tenant predicate + grant LOGIN to the app role

Revision ID: c3e7a15d8b92
Revises: b8d4f1c07e35
Create Date: 2026-08-14

Phase 2 of the RLS remediation. Both changes are INERT for the current
connection: the app still connects as `shieldscan`, a SUPERUSER with BYPASSRLS,
which bypasses policies regardless of how they are written, and the app role
gets LOGIN but no password so it cannot yet authenticate. This migration can
therefore land well ahead of the cutover, and rolling the cutover back needs no
database change at all — only pointing DATABASE_URL back at the owner role.

Background: RLS is enabled and FORCED on all 13 tenant tables with a
`tenant_isolation` policy, but the application has always connected as the
superuser owner, so the policies have never been evaluated in production.
Tenant isolation currently rests entirely on application-layer
`WHERE organization_id = ...` clauses. The test fixture does `SET ROLE
shieldscan_app`, so the suite exercises the enforced path and passes — which is
why nothing detected the gap.

--- Change 1: null-safe tenant predicate -----------------------------------

The policy predicate becomes:

    organization_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid

Every part is load-bearing, established by probing a real non-superuser role
against a real RLS'd table:

  state of the GUC                     one-arg      two-arg      + NULLIF
  -----------------------------------  -----------  -----------  ---------
  never set in this session            RAISES       0 rows       0 rows
  set to an org                        1 row        1 row        1 row
  SET LOCAL reverted by COMMIT         RAISES       RAISES       0 rows
  after an explicit RESET              RAISES       RAISES       0 rows

The one-argument form turns a missed tenant context into a hard 500. The
two-argument form alone is NOT sufficient: once the parameter has been touched
in a session, clearing it leaves an EMPTY STRING rather than NULL, and
``''::uuid`` raises `invalid input syntax for type uuid`. Those two rows are
not hypothetical — they are exactly the states produced by a connection-reset
handler and by a mid-request commit (routes/projects.py commits, then reads
project_credentials in the same request).

With NULLIF, a missing GUC yields NULL, the comparison yields NULL, and the row
is filtered out: zero rows, no error. A missed tenant context can never mean
"all rows", and it never means a 500 either.

--- Change 2: LOGIN on the app role ----------------------------------------

`shieldscan_app` was created NOSUPERUSER NOBYPASSRLS NOINHERIT with no LOGIN,
because the original design had the app connect as the owner and SET ROLE down.
The remediation connects AS the role instead: SET ROLE from a superuser
connection leaves the pooled connection superuser, so it fails OPEN for any
call site that forgets to opt in — a consumer, a script, a future get_db
variant. Connecting as the role fails closed by default.

No password is set here. Passwords do not belong in a migration; it is applied
out-of-band (ALTER ROLE ... PASSWORD) alongside the DATABASE_URL change. Until
then the role holds LOGIN but cannot authenticate, so this remains inert.

The role already holds SELECT/INSERT/UPDATE/DELETE on all tables plus schema
and sequence usage, including tables created after it was provisioned (verified
against the live database: all 21 tables), via ALTER DEFAULT PRIVILEGES.
"""

from typing import Sequence, Union

from alembic import op

from app.db.policies import TENANT_PREDICATE, TENANT_TABLES

revision: str = "c3e7a15d8b92"
down_revision: Union[str, Sequence[str], None] = "b8d4f1c07e35"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# The predicate this migration replaces. Inlined rather than imported: a
# downgrade must restore what was actually there, and policies.py now holds the
# new form.
_OLD_PREDICATE = "organization_id = current_setting('app.current_org_id')::uuid"


def upgrade() -> None:
    # Policies cannot be altered in place; drop and recreate per table.
    # TENANT_TABLES/TENANT_PREDICATE are imported so this migration and the
    # test fixture cannot drift apart (the existing policies.py contract).
    for table in TENANT_TABLES:
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {table};")
        op.execute(
            f"CREATE POLICY tenant_isolation ON {table} "
            f"USING ({TENANT_PREDICATE}) "
            f"WITH CHECK ({TENANT_PREDICATE});"
        )

    # Idempotent: rerunnable, and a no-op if the role somehow already has LOGIN.
    op.execute(
        "DO $$ BEGIN "
        "  IF EXISTS (SELECT 1 FROM pg_roles "
        "             WHERE rolname = 'shieldscan_app' AND NOT rolcanlogin) "
        "  THEN ALTER ROLE shieldscan_app WITH LOGIN; "
        "  END IF; "
        "END $$;"
    )


def downgrade() -> None:
    op.execute(
        "DO $$ BEGIN "
        "  IF EXISTS (SELECT 1 FROM pg_roles "
        "             WHERE rolname = 'shieldscan_app' AND rolcanlogin) "
        "  THEN ALTER ROLE shieldscan_app WITH NOLOGIN; "
        "  END IF; "
        "END $$;"
    )
    for table in TENANT_TABLES:
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {table};")
        op.execute(
            f"CREATE POLICY tenant_isolation ON {table} "
            f"USING ({_OLD_PREDICATE}) "
            f"WITH CHECK ({_OLD_PREDICATE});"
        )
