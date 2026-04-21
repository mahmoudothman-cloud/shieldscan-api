"""enable row-level security and audit-log triggers

Revision ID: 5b30069416cd
Revises: 846aa1515341
Create Date: 2026-04-21

Enables tenant_isolation RLS on 12 tenant-scoped tables, installs the
append-only triggers on audit_logs, and provisions the non-superuser
`shieldscan_app` role the application (and tests) use for runtime
queries — superusers bypass RLS unconditionally, so the POSTGRES_USER
owner role cannot be what serves requests.
"""

from typing import Sequence, Union

from alembic import op

from app.db.policies import (
    app_role_downgrade_sql,
    app_role_upgrade_sql,
    audit_triggers_downgrade_sql,
    audit_triggers_upgrade_sql,
    rls_downgrade_sql,
    rls_upgrade_sql,
)

revision: str = "5b30069416cd"
down_revision: Union[str, Sequence[str], None] = "846aa1515341"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    for sql in rls_upgrade_sql():
        op.execute(sql)
    for sql in audit_triggers_upgrade_sql():
        op.execute(sql)
    for sql in app_role_upgrade_sql():
        op.execute(sql)


def downgrade() -> None:
    for sql in app_role_downgrade_sql():
        op.execute(sql)
    for sql in audit_triggers_downgrade_sql():
        op.execute(sql)
    for sql in rls_downgrade_sql():
        op.execute(sql)
