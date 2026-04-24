"""remove api_keys from RLS (credential-indexed-table carve-out, ADR-012)

Revision ID: 9a4e2c1b7d3f
Revises: 5b30069416cd
Create Date: 2026-04-21

Rationale: API-key authentication is a lookup-by-credential-hash that
MUST precede establishing tenant context — the row is what tells us
which org the caller belongs to. RLS requires the GUC
`app.current_org_id` to be set BEFORE the SELECT, which creates a
chicken-and-egg problem: we can't set the GUC without knowing the
org, and we can't know the org without reading the row that RLS is
gating.

Resolution: drop RLS from api_keys; enforce tenant scoping at the
application layer instead. The key_hash column is unique + indexed
and cryptographically unguessable — cross-tenant reads by hash are
infeasible without the plaintext, which already authenticates the
reader for that org.

See ADR-012 in SPECIFICATION.md for the full analysis, including
alternatives considered and rejected (SECURITY DEFINER, GUC carve-out,
prefix-encoded org id).
"""

from typing import Sequence, Union

from alembic import op

revision: str = "9a4e2c1b7d3f"
down_revision: Union[str, Sequence[str], None] = "5b30069416cd"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Order matters: drop the policy first, then NO FORCE, then DISABLE.
    # Reversing this order works too but the chosen sequence mirrors the
    # original rls_upgrade_sql DDL in reverse.
    op.execute("DROP POLICY IF EXISTS tenant_isolation ON api_keys;")
    op.execute("ALTER TABLE api_keys NO FORCE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE api_keys DISABLE ROW LEVEL SECURITY;")


def downgrade() -> None:
    # Reverse: re-enable + re-force + reinstall the tenant_isolation
    # policy exactly as rls_upgrade_sql emits it for the other tables.
    op.execute("ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE api_keys FORCE ROW LEVEL SECURITY;")
    op.execute(
        "CREATE POLICY tenant_isolation ON api_keys "
        "USING (organization_id = current_setting('app.current_org_id')::uuid) "
        "WITH CHECK (organization_id = current_setting('app.current_org_id')::uuid);"
    )
