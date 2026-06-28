"""add_m9b_correlation_scoring_columns

Revision ID: ecfed70e05e4
Revises: b7e4a1f93c2d
Create Date: 2026-06-28 08:17:00.484916

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'ecfed70e05e4'
down_revision: Union[str, Sequence[str], None] = 'b7e4a1f93c2d'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema (M9.B ADR-031 Q16: correlation + scoring columns).

    correlation_cluster_id: union-find cluster grouping id (Q8; nullable, indexed
    for the Y2 DISTINCT(correlation_cluster_id) vulnerability_count adapter). Not a
    foreign key — it is a cluster-grouping UUID, not a row reference.
    severity_score: composite §8.3 final_score (Q11; nullable, not indexed —
    M10 ranking index forward-pinned).
    """
    op.add_column(
        "vulnerabilities",
        sa.Column("correlation_cluster_id", sa.UUID(), nullable=True),
    )
    op.create_index(
        "ix_vulnerabilities_correlation_cluster_id",
        "vulnerabilities",
        ["correlation_cluster_id"],
    )
    op.add_column(
        "vulnerabilities",
        sa.Column("severity_score", sa.Float(), nullable=True),
    )


def downgrade() -> None:
    """Downgrade schema (explicit per Q16)."""
    op.drop_column("vulnerabilities", "severity_score")
    op.drop_index(
        "ix_vulnerabilities_correlation_cluster_id",
        table_name="vulnerabilities",
    )
    op.drop_column("vulnerabilities", "correlation_cluster_id")
