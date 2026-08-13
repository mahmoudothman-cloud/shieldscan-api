"""add tool_metadata to raw_findings

Engine RawFinding.Metadata (events.go:169, `metadata,omitempty`) had no
landing column; ingest rejected every finding from nmap/zap/mobsf/trivy
via extra="forbid". Column named tool_metadata because `metadata` is
reserved on SQLAlchemy Declarative classes; bridged by
Field(alias="metadata") in schemas/raw_findings.py.

Revision ID: b8d4f1c07e35
Revises: a7c3e9f04b21
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "b8d4f1c07e35"
down_revision = "a7c3e9f04b21"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "raw_findings",
        sa.Column(
            "tool_metadata",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("raw_findings", "tool_metadata")
