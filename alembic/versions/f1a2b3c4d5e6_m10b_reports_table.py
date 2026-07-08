"""m10b reports table

Revision ID: f1a2b3c4d5e6
Revises: ecfed70e05e4
Create Date: 2026-07-08 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "f1a2b3c4d5e6"
down_revision: Union[str, Sequence[str], None] = "ecfed70e05e4"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema (M10.B ADR-034 G1: reports table).

    Standard TenantMixin + RLS table per Gotcha 3 — Python api sole-writer
    per ADR-013. The inline RLS block mirrors app.db.policies.rls_upgrade_sql()
    (the b7e4a1f93c2d ai_api_calls idiom); "reports" is also registered in
    TENANT_TABLES so tests/conftest.py applies the same policy via create_all.
    """
    op.create_table(
        "reports",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("scan_id", sa.UUID(), nullable=False),
        sa.Column(
            "format",
            sa.Enum("pdf", "sarif", "json", name="report_format"),
            nullable=False,
        ),
        sa.Column("r2_key", sa.String(length=500), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_reports_scan_id"), "reports", ["scan_id"], unique=False
    )
    op.create_index(
        op.f("ix_reports_organization_id"),
        "reports",
        ["organization_id"],
        unique=False,
    )

    # RLS for reports — mirrors app.db.policies.rls_upgrade_sql() exactly
    # (reports is registered in TENANT_TABLES so tests/conftest.py applies it
    # via create_all). Standard TenantMixin+RLS per Gotcha 3.
    op.execute("ALTER TABLE reports ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE reports FORCE ROW LEVEL SECURITY;")
    op.execute(
        "CREATE POLICY tenant_isolation ON reports "
        "USING (organization_id = current_setting('app.current_org_id')::uuid) "
        "WITH CHECK (organization_id = current_setting('app.current_org_id')::uuid);"
    )


def downgrade() -> None:
    """Downgrade schema (drop_table cascades the policy + indexes)."""
    op.drop_index(op.f("ix_reports_organization_id"), table_name="reports")
    op.drop_index(op.f("ix_reports_scan_id"), table_name="reports")
    op.drop_table("reports")
    op.execute("DROP TYPE IF EXISTS report_format;")
