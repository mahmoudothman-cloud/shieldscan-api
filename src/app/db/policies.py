"""Row-Level Security policies + audit-log append-only triggers.

Single source of truth for both the Alembic migration and the test fixture
(`tests/conftest.py`), so production and test DBs stay in lock-step.

Security model
--------------
Every tenant-scoped table has:
  * ROW LEVEL SECURITY enabled AND FORCED (so even the table owner is
    subject to the policy — no accidental bypass in migrations or dev).
  * A `tenant_isolation` policy gated on the session-local GUC
    `app.current_org_id`:

        USING (organization_id = current_setting('app.current_org_id')::uuid)
        WITH CHECK (organization_id = current_setting('app.current_org_id')::uuid)

The app layer sets this GUC at the start of every request from the JWT
org claim; tests set it via `tests.conftest.use_org`.

audit_logs is additionally protected by BEFORE-UPDATE and BEFORE-DELETE
triggers that raise, making it true append-only at the DB layer
(CONSTITUTION §14.6, retention per SPEC §5.4).
"""

from __future__ import annotations

from collections.abc import Iterable

# Tables that live at end of M1 AND carry organization_id. Must match the
# audit list in response C of the design audit. Non-tenant tables
# (organizations, users, memberships) are excluded by design.
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
    "api_keys",
)


def rls_upgrade_sql() -> Iterable[str]:
    """Yield the DDL statements that enable RLS + install the policy."""
    for table in TENANT_TABLES:
        yield f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;"
        # FORCE makes the policy apply to the table owner too; without this
        # the Postgres role that owns the table silently bypasses RLS.
        yield f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY;"
        yield (
            f"CREATE POLICY tenant_isolation ON {table} "
            f"USING (organization_id = current_setting('app.current_org_id')::uuid) "
            f"WITH CHECK (organization_id = current_setting('app.current_org_id')::uuid);"
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


# Non-superuser role that the application (and tests via SET ROLE) use
# for all runtime queries. Superusers bypass RLS *unconditionally*, so the
# owner role (`shieldscan`) cannot be what serves requests. This role is
# created idempotently so the migration is rerunnable.
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
