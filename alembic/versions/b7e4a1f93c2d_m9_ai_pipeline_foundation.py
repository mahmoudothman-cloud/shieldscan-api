"""m9_ai_pipeline_foundation: ai_api_calls table + scan/vulnerability/raw_finding columns

Revision ID: b7e4a1f93c2d
Revises: 49e83eb3587c
Create Date: 2026-06-12

ADR-029 reference (SPEC §13; commit 45dcabe). M9.0 Stage 3 C1 — single migration
per Q9 (A.a); lands at M9.0 Stage 3 first-implementation-commit per Q9 (B.a);
forward-only per Q9 (C.c) pre-launch context (explicit downgrade() forward-pinned
for production-readiness audit per ADR-029 Consequences).

Drift closures (resolving code per Stage 1 design doc a46fedd §9 + plan 55dbe32 §5):
- Drift #64 (ai_api_calls absence; Drift #60 catch-class 4th-instance:
  stored-design-intent-with-unimplemented-mechanism per CLAUDE.md Gotcha 5)
- Drift #65 (Scan.executive_summary absence; Drift #61 catch-class 5th-instance:
  concrete-empirical-field absence sub-category 2nd-instance)

ai_api_calls is a tenant-scoped table: registered in app.db.policies.TENANT_TABLES
(single source of truth consumed by tests/conftest.py create_all + RLS application);
this migration applies the same RLS DDL explicitly for production, since the original
RLS migration (5b30069416cd) predates this table.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers
revision: str = "b7e4a1f93c2d"
down_revision: Union[str, Sequence[str], None] = "49e83eb3587c"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # --- ai_api_calls table (ADR-029 Q2 Phase-2 cost tracking) ---
    op.create_table(
        "ai_api_calls",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("scan_id", sa.UUID(), nullable=False),
        sa.Column("provider", sa.String(length=50), nullable=False),
        sa.Column("model", sa.String(length=100), nullable=False),
        sa.Column("operation_type", sa.String(length=50), nullable=False),
        sa.Column("tokens_in", sa.Integer(), nullable=False),
        sa.Column("tokens_out", sa.Integer(), nullable=True),
        sa.Column("cost_usd", sa.Numeric(precision=10, scale=6), nullable=False),
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
        op.f("ix_ai_api_calls_scan_id"), "ai_api_calls", ["scan_id"], unique=False
    )
    op.create_index(
        op.f("ix_ai_api_calls_organization_id"),
        "ai_api_calls",
        ["organization_id"],
        unique=False,
    )

    # RLS for ai_api_calls — mirrors app.db.policies.rls_upgrade_sql() exactly
    # (5b30069416cd applied this to the original tenant tables; ai_api_calls is
    # registered in TENANT_TABLES so tests/conftest.py applies it via create_all).
    op.execute("ALTER TABLE ai_api_calls ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE ai_api_calls FORCE ROW LEVEL SECURITY;")
    op.execute(
        "CREATE POLICY tenant_isolation ON ai_api_calls "
        "USING (organization_id = current_setting('app.current_org_id')::uuid) "
        "WITH CHECK (organization_id = current_setting('app.current_org_id')::uuid);"
    )

    # --- Scan columns (ADR-029 Q3 Phase-3 + Q8 Phase-8) ---
    op.add_column("scans", sa.Column("executive_summary", sa.Text(), nullable=True))
    op.add_column(
        "scans",
        sa.Column(
            "ai_pipeline_degraded",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
    )

    # --- Vulnerability columns (ADR-029 Q5 Phase-5 + Q6 Phase-6) ---
    op.add_column(
        "vulnerabilities", sa.Column("qdrant_point_id", sa.UUID(), nullable=True)
    )
    op.add_column(
        "vulnerabilities",
        sa.Column("raw_finding_ids", sa.ARRAY(sa.UUID()), nullable=True),
    )

    # --- raw_findings columns (ADR-029 Q6 Phase-6) ---
    op.add_column(
        "raw_findings",
        sa.Column("promoted_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "raw_findings", sa.Column("vulnerability_id", sa.UUID(), nullable=True)
    )
    op.create_foreign_key(
        "fk_raw_findings_vulnerability_id",
        "raw_findings",
        "vulnerabilities",
        ["vulnerability_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index(
        op.f("ix_raw_findings_vulnerability_id"),
        "raw_findings",
        ["vulnerability_id"],
        unique=False,
    )


def downgrade() -> None:
    raise NotImplementedError(
        "Forward-only per M9.0 ADR-029 Q9 (C.c) pre-launch context. Explicit "
        "downgrade() implementation forward-pinned for production-readiness audit "
        "(ADR-029 Consequences)."
    )
