"""public_scans table (M11 pre-work; ADDENDUM-CRITICAL-5 §2)

Revision ID: a1d9e7c2f5b8
Revises: e4b8c2a71f36
Create Date: 2026-11-07 14:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "a1d9e7c2f5b8"
down_revision: Union[str, Sequence[str], None] = "e4b8c2a71f36"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Public quick-scan request records, addressed by an unguessable slug.

    Standard TenantMixin + RLS table (Gotcha 3); organization_id is always
    the system public-scan org. Registered in TENANT_TABLES so the test
    harness applies the same policy via create_all.
    """
    op.create_table(
        "public_scans",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("slug", sa.String(length=64), nullable=False),
        sa.Column("scan_id", sa.UUID(), nullable=False),
        sa.Column("project_id", sa.UUID(), nullable=False),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("target_url", sa.String(length=500), nullable=False),
        sa.Column("normalized_domain", sa.String(length=255), nullable=False),
        sa.Column("ip_address", sa.String(length=45), nullable=True),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.Column("consent_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("viewed_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("converted_org_id", sa.UUID(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["converted_org_id"], ["organizations.id"], ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("slug"),
        sa.UniqueConstraint("scan_id"),
    )
    op.create_index(op.f("ix_public_scans_slug"), "public_scans", ["slug"], unique=True)
    op.create_index(op.f("ix_public_scans_email"), "public_scans", ["email"], unique=False)
    op.create_index(
        op.f("ix_public_scans_normalized_domain"),
        "public_scans",
        ["normalized_domain"],
        unique=False,
    )
    op.create_index(
        op.f("ix_public_scans_organization_id"),
        "public_scans",
        ["organization_id"],
        unique=False,
    )

    # RLS — mirrors app.db.policies.rls_upgrade_sql() exactly.
    op.execute("ALTER TABLE public_scans ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE public_scans FORCE ROW LEVEL SECURITY;")
    op.execute(
        "CREATE POLICY tenant_isolation ON public_scans "
        "USING (organization_id = current_setting('app.current_org_id')::uuid) "
        "WITH CHECK (organization_id = current_setting('app.current_org_id')::uuid);"
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_public_scans_organization_id"), table_name="public_scans")
    op.drop_index(op.f("ix_public_scans_normalized_domain"), table_name="public_scans")
    op.drop_index(op.f("ix_public_scans_email"), table_name="public_scans")
    op.drop_index(op.f("ix_public_scans_slug"), table_name="public_scans")
    op.drop_table("public_scans")
