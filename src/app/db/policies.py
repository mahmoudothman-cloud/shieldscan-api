"""Row-Level Security policies + audit-log append-only triggers.

Single source of truth for both the Alembic migration and the test fixture
(`tests/conftest.py`), so production and test DBs stay in lock-step.

Security model — two categories of tenant-scoped tables
-------------------------------------------------------
**TENANT_TABLES** — the default. Each table in this list has:
  * ROW LEVEL SECURITY enabled AND FORCED (so even the table owner is
    subject to the policy — no accidental bypass in migrations or dev).
  * A `tenant_isolation` policy gated on the session-local GUC
    `app.current_org_id`:

        USING (organization_id = current_setting('app.current_org_id')::uuid)
        WITH CHECK (organization_id = current_setting('app.current_org_id')::uuid)

  The app layer sets the GUC at the start of every request from the JWT
  org claim; tests set it via `tests.conftest.use_org`.

**CREDENTIAL_INDEXED_TABLES** — the deliberate carve-out (see ADR-012).
  These tables have NO RLS policy because their primary access pattern
  is lookup-by-opaque-credential (e.g. SHA-256 of an API key plaintext),
  which MUST precede establishing tenant context — the row is what tells
  us which org the caller belongs to. Tenant scoping for these tables is
  enforced at the **application layer** instead: every query either
  matches on the credential hash (proof of ownership) or explicitly
  filters `WHERE organization_id = :authenticated_org`.

  **Adding a table here requires an ADR amendment**, not just a code
  change — the bar is deliberately high. The justification string in
  CREDENTIAL_INDEXED_TABLES is the forcing function for code review.

audit_logs is additionally protected by BEFORE-UPDATE and BEFORE-DELETE
triggers that raise, making it true append-only at the DB layer
(CONSTITUTION §14.6, retention per SPEC §5.4).
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Final

# Default tenant-scoped tables — RLS-enforced at the DB layer.
# Non-tenant tables (organizations, users, memberships) are excluded by
# design. For the deliberate carve-out from RLS, see
# CREDENTIAL_INDEXED_TABLES below.
TENANT_TABLES: tuple[str, ...] = (
    "projects",
    "project_credentials",
    "scans",
    "scan_jobs",
    "raw_findings",
    "vulnerabilities",
    "evidence",
    "vulnerability_history",
    "mobile_uploads",
    "attack_surface",
    "audit_logs",
    "ai_api_calls",  # ADR-029 M9.0 — AI cost tracking; tenant-scoped (Gotcha 3)
    "reports",  # ADR-034 M10.B — report artifacts; tenant-scoped (Gotcha 3)
    "public_scans",  # M11 pre-work — public quick-scan requests; owned by the system org
)


# Tables that bypass RLS because their row identifier IS the credential.
# See ADR-012 in SPECIFICATION.md for the full reasoning. Adding a table
# to this dict REQUIRES an ADR amendment — not just a code change.
CREDENTIAL_INDEXED_TABLES: Final[dict[str, str]] = {
    "api_keys": (
        "Rows identified by SHA-256(plaintext). Lookup by hash IS "
        "authentication; RLS would prevent the lookup from succeeding "
        "because tenant context is the RESULT of the lookup, not its "
        "precondition. Tenant scoping enforced at the application layer "
        "(see routes/api_keys.py list + delete handlers). See ADR-012."
    ),
}


# The tenant predicate, shared by USING and WITH CHECK.
#
# Three deliberate parts, each empirically justified — see the RLS entry in
# DRIFT-LOG.md for the probe output:
#
#   current_setting(..., true)  two-argument form. The one-argument form RAISES
#                               `unrecognized configuration parameter` when the
#                               GUC was never set, turning a missed tenant
#                               context into a hard 500 instead of a safe empty
#                               result.
#   NULLIF(..., '')             REQUIRED, not belt-and-braces. Once the GUC has
#                               been touched in a session, clearing it (RESET,
#                               or a SET LOCAL reverting at commit) leaves an
#                               EMPTY STRING, not NULL — and ''::uuid raises
#                               `invalid input syntax for type uuid`. Without
#                               NULLIF the two-argument form still 500s in
#                               exactly the states a connection-reset handler
#                               and a mid-request commit produce.
#   ::uuid                      organization_id is uuid; NULL propagates, so a
#                               missing GUC makes the predicate NULL → zero
#                               rows. A missed tenant context can never mean
#                               "all rows".
TENANT_PREDICATE = (
    "organization_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid"
)


def rls_upgrade_sql() -> Iterable[str]:
    """Yield the DDL statements that enable RLS + install the policy."""
    for table in TENANT_TABLES:
        yield f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;"
        # FORCE makes the policy apply to the table owner too; without this
        # the Postgres role that owns the table silently bypasses RLS.
        #
        # NOTE: FORCE does NOT constrain a SUPERUSER or a BYPASSRLS role. The
        # application must connect as a role holding neither — see
        # APP_ROLE_NAME below.
        yield f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY;"
        yield (
            f"CREATE POLICY tenant_isolation ON {table} "
            f"USING ({TENANT_PREDICATE}) "
            f"WITH CHECK ({TENANT_PREDICATE});"
        )


def rls_downgrade_sql() -> Iterable[str]:
    for table in TENANT_TABLES:
        yield f"DROP POLICY IF EXISTS tenant_isolation ON {table};"
        yield f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY;"
        yield f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY;"


# BEFORE-UPDATE / BEFORE-DELETE triggers on audit_logs raising
# `audit_logs is append-only` — CONSTITUTION §14.6.
AUDIT_APPEND_ONLY_FUNCTION = """
CREATE OR REPLACE FUNCTION prevent_audit_log_mutation()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'audit_logs is append-only: % operations are forbidden',
                    TG_OP;
END;
$$ LANGUAGE plpgsql;
"""

AUDIT_APPEND_ONLY_TRIGGERS = (
    "CREATE TRIGGER audit_logs_no_update "
    "BEFORE UPDATE ON audit_logs "
    "FOR EACH ROW EXECUTE FUNCTION prevent_audit_log_mutation();",
    "CREATE TRIGGER audit_logs_no_delete "
    "BEFORE DELETE ON audit_logs "
    "FOR EACH ROW EXECUTE FUNCTION prevent_audit_log_mutation();",
)


def audit_triggers_upgrade_sql() -> Iterable[str]:
    yield AUDIT_APPEND_ONLY_FUNCTION
    yield from AUDIT_APPEND_ONLY_TRIGGERS


def audit_triggers_downgrade_sql() -> Iterable[str]:
    yield "DROP TRIGGER IF EXISTS audit_logs_no_update ON audit_logs;"
    yield "DROP TRIGGER IF EXISTS audit_logs_no_delete ON audit_logs;"
    yield "DROP FUNCTION IF EXISTS prevent_audit_log_mutation();"


# Non-superuser role that the application uses for all runtime queries.
# Superusers bypass RLS *unconditionally*, so the owner role (`shieldscan`)
# cannot be what serves requests. Created idempotently so the migration is
# rerunnable.
#
# HISTORY — this role was provisioned by dbdccfd, whose commit message states
# "The app connects / tests SET ROLE to this". Only the tests half shipped: no
# SET ROLE, and no connection as this role, ever existed in src/. The app has
# been serving every request as the superuser owner, so the policies above were
# never evaluated in production while the suite — which does SET ROLE in its
# fixture — reported tenant isolation as verified.
#
# The remediation connects the app AS this role (rather than SET ROLE from a
# superuser connection, which leaves pooled connections superuser and fails
# open for any call site that forgets to opt in). That requires LOGIN, granted
# by the migration; the password is set out-of-band so no secret enters git.
APP_ROLE_NAME = "shieldscan_app"


def app_role_upgrade_sql() -> Iterable[str]:
    yield (
        f"DO $$ BEGIN "
        f"  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{APP_ROLE_NAME}') "
        f"  THEN CREATE ROLE {APP_ROLE_NAME} NOSUPERUSER NOBYPASSRLS NOINHERIT; "
        f"  END IF; "
        f"END $$;"
    )
    yield f"GRANT USAGE ON SCHEMA public TO {APP_ROLE_NAME};"
    yield (
        f"GRANT SELECT, INSERT, UPDATE, DELETE "
        f"ON ALL TABLES IN SCHEMA public TO {APP_ROLE_NAME};"
    )
    yield (
        f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public "
        f"TO {APP_ROLE_NAME};"
    )
    # Future tables / sequences inherit these grants without a fresh migration.
    yield (
        f"ALTER DEFAULT PRIVILEGES IN SCHEMA public "
        f"GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {APP_ROLE_NAME};"
    )
    yield (
        f"ALTER DEFAULT PRIVILEGES IN SCHEMA public "
        f"GRANT USAGE, SELECT ON SEQUENCES TO {APP_ROLE_NAME};"
    )


def app_role_downgrade_sql() -> Iterable[str]:
    yield (
        f"ALTER DEFAULT PRIVILEGES IN SCHEMA public "
        f"REVOKE SELECT, INSERT, UPDATE, DELETE ON TABLES FROM {APP_ROLE_NAME};"
    )
    yield (
        f"ALTER DEFAULT PRIVILEGES IN SCHEMA public "
        f"REVOKE USAGE, SELECT ON SEQUENCES FROM {APP_ROLE_NAME};"
    )
    yield (
        f"REVOKE ALL ON ALL TABLES IN SCHEMA public FROM {APP_ROLE_NAME};"
    )
    yield (
        f"REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM {APP_ROLE_NAME};"
    )
    yield f"REVOKE USAGE ON SCHEMA public FROM {APP_ROLE_NAME};"
    yield f"DROP ROLE IF EXISTS {APP_ROLE_NAME};"
